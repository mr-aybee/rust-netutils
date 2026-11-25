//! Polling rounds and the watch / wait / compare workflows.

use crate::query::{Answer, Source, diff, query};
use hickory_resolver::proto::rr::RecordType;
use net_common::time::{iso8601, now_unix};
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

/// One (name, type) pair to query on every source.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Query {
    pub name: String,
    pub rtype: RecordType,
}

/// Query every (query, source) pair with at most `concurrency` in flight.
/// Result index = query_index * sources.len() + source_index.
pub async fn poll(
    sources: &Arc<Vec<Source>>,
    queries: &Arc<Vec<Query>>,
    concurrency: usize,
) -> Vec<Answer> {
    let total = queries.len() * sources.len();
    let mut out: Vec<Option<Answer>> = vec![None; total];
    let mut next = 0usize;
    let mut set = JoinSet::new();
    let spawn = |set: &mut JoinSet<(usize, Answer)>, i: usize| {
        let (sources, queries) = (Arc::clone(sources), Arc::clone(queries));
        set.spawn(async move {
            let q = &queries[i / sources.len()];
            let s = &sources[i % sources.len()];
            (i, query(&s.resolver, &q.name, q.rtype).await)
        });
    };

    while next < total.min(concurrency.max(1)) {
        spawn(&mut set, next);
        next += 1;
    }

    while let Some(res) = set.join_next().await {
        if let Ok((i, a)) = res {
            out[i] = Some(a);
        }

        if next < total {
            spawn(&mut set, next);
            next += 1;
        }
    }

    out.into_iter()
        .map(|a| a.unwrap_or_else(|| Answer::Error("internal task failure".into())))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Initial,
    Changed,
    Error,
    Recovered,
}

#[derive(Debug, Serialize)]
pub struct Event<'a> {
    pub time: String,
    pub event: Kind,
    pub name: &'a str,
    #[serde(rename = "type")]
    pub rtype: String,
    pub server: &'a str,
    pub answer: &'a Answer,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<&'a Answer>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub added: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
}

pub fn emit(e: &Event<'_>, json: bool) {
    let line = if json {
        serde_json::to_string(e).unwrap_or_default()
    } else {
        let label = match e.event {
            Kind::Initial => "INITIAL",
            Kind::Changed => "CHANGED",
            Kind::Error => "ERROR",
            Kind::Recovered => "RECOVERED",
        };

        let mut s = format!(
            "{}  {label:<9} {} {} @{}  ",
            e.time, e.name, e.rtype, e.server
        );

        if e.event == Kind::Changed && (!e.added.is_empty() || !e.removed.is_empty()) {
            let parts: Vec<String> = e
                .added
                .iter()
                .map(|a| format!("+ {a}"))
                .chain(e.removed.iter().map(|r| format!("- {r}")))
                .collect();
            s.push_str(&parts.join("  "));
        } else if let (Kind::Changed, Some(prev)) = (e.event, e.previous) {
            s.push_str(&format!("{} -> {}", prev.summary(), e.answer.summary()));
        } else {
            s.push_str(&e.answer.summary());
        }

        s
    };

    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

/// Settings shared by the workflows.
pub struct Settings {
    pub interval: Duration,
    pub concurrency: usize,
    pub json: bool,
}

/// Poll forever (or until a change with `until_change`). Returns true if a change was seen.
pub async fn watch(
    sources: Arc<Vec<Source>>,
    queries: Arc<Vec<Query>>,
    s: &Settings,
    until_change: bool,
    quiet_initial: bool,
) -> bool {
    let mut last: HashMap<usize, Answer> = HashMap::new(); // last definitive answer
    let mut failing: HashMap<usize, bool> = HashMap::new();
    let mut ticker = tokio::time::interval(s.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut changed_any = false;

    loop {
        ticker.tick().await;
        let answers = poll(&sources, &queries, s.concurrency).await;
        let time = iso8601(now_unix());

        for (i, ans) in answers.iter().enumerate() {
            let q = &queries[i / sources.len()];
            let src = &sources[i % sources.len()].label;
            let base = |event, previous, added, removed| Event {
                time: time.clone(),
                event,
                name: &q.name,
                rtype: q.rtype.to_string(),
                server: src,
                answer: ans,
                previous,
                added,
                removed,
            };

            if !ans.is_definitive() {
                // Report each failure streak once; never treat it as a change.
                if !failing.insert(i, true).unwrap_or(false) {
                    emit(&base(Kind::Error, last.get(&i), vec![], vec![]), s.json);
                }

                continue;
            }

            if failing.remove(&i).unwrap_or(false) && last.get(&i) == Some(ans) {
                emit(&base(Kind::Recovered, None, vec![], vec![]), s.json);
            }

            match last.get(&i) {
                None => {
                    if !quiet_initial {
                        emit(&base(Kind::Initial, None, vec![], vec![]), s.json);
                    }
                }
                Some(prev) if prev != ans => {
                    let (added, removed) = diff(prev, ans);
                    emit(&base(Kind::Changed, Some(prev), added, removed), s.json);
                    changed_any = true;
                }
                Some(_) => {}
            }

            last.insert(i, ans.clone());
        }

        if until_change && changed_any {
            return true;
        }
    }
}

/// Poll until every source returns exactly `expected` values for every query.
pub async fn wait(
    sources: Arc<Vec<Source>>,
    queries: Arc<Vec<Query>>,
    s: &Settings,
    expected: &[String],
) -> bool {
    let mut want: Vec<String> = expected
        .iter()
        .map(|e| e.trim().trim_end_matches('.').to_ascii_lowercase())
        .collect();
    want.sort_unstable();
    want.dedup();
    let mut ticker = tokio::time::interval(s.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;
        let answers = poll(&sources, &queries, s.concurrency).await;
        let mut matched = 0;
        let mut pending = Vec::new();

        for (i, ans) in answers.iter().enumerate() {
            let q = &queries[i / sources.len()];
            let mut got: Vec<String> = ans
                .values_of(q.rtype)
                .iter()
                .map(|v| v.trim_end_matches('.').to_ascii_lowercase())
                .collect();
            got.sort_unstable();
            got.dedup();

            if got == want {
                matched += 1;
            } else {
                pending.push(format!(
                    "{} {} @{}: {}",
                    q.name,
                    q.rtype,
                    sources[i % sources.len()].label,
                    ans.summary()
                ));
            }
        }

        let time = iso8601(now_unix());

        if s.json {
            let doc = serde_json::json!({"time": time, "matched": matched, "total": answers.len(), "pending": pending});
            let _ = writeln!(std::io::stdout().lock(), "{doc}");
        } else {
            let _ = writeln!(
                std::io::stdout().lock(),
                "{time}  {matched}/{} matching{}",
                answers.len(),
                if pending.is_empty() {
                    String::new()
                } else {
                    format!("; waiting on: {}", pending.join("; "))
                }
            );
        }

        if matched == answers.len() {
            return true;
        }
    }
}

/// Result of a one-shot comparison of all sources.
#[derive(Debug, Serialize)]
pub struct Comparison {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub consistent: bool,
    pub answers: Vec<(String, Answer)>,
}

pub async fn compare(
    sources: Arc<Vec<Source>>,
    queries: Arc<Vec<Query>>,
    concurrency: usize,
) -> Vec<Comparison> {
    let answers = poll(&sources, &queries, concurrency).await;
    queries
        .iter()
        .enumerate()
        .map(|(qi, q)| {
            let row: Vec<(String, Answer)> = (0..sources.len())
                .map(|si| {
                    (
                        sources[si].label.clone(),
                        answers[qi * sources.len() + si].clone(),
                    )
                })
                .collect();
            let definitive: Vec<&Answer> = row
                .iter()
                .map(|(_, a)| a)
                .filter(|a| a.is_definitive())
                .collect();
            let consistent =
                definitive.len() == row.len() && definitive.windows(2).all(|w| w[0] == w[1]);
            Comparison {
                name: q.name.clone(),
                rtype: q.rtype.to_string(),
                consistent,
                answers: row,
            }
        })
        .collect()
}
