// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//
// Raft consensus algorithm.

use uuid::Uuid;
use std::collections::BTreeMap;

pub struct Term(u64);

impl Term {
    pub fn new(number: u64) -> Term {
        Term(number)
    }

    pub fn to_number(&self) -> u64 {
        match self {
            &Term(u) => u
        }
    }

    pub fn next(&self) -> Term {
        match self {
            &Term(u) => Term(u + 1)
        }
    }
}

pub struct LogEntry {
    pub term: Term,
    pub command: String,
}

pub enum Role {
    Follower,
    Candidate,
    Leader(LeaderState),
}

pub struct LeaderState {
    pub next_index: BTreeMap<Uuid, u64>,
    pub match_index: BTreeMap<Uuid, u64>,
}

pub struct RaftState {
    pub this_id: Uuid,
    pub state_directory: String,
    pub current_term: Term,      // Persistent state
    pub voted_for: Option<Uuid>, // Persistent state
    pub log: Vec<LogEntry>,      // Persistent state
    pub commit_index: u64,       // Volatile state
    pub last_applied: u64,       // Volatile state
    pub role: Role,              // Volatile state
}

impl RaftState {
    pub fn new(uuid: Uuid, state_dir: String) -> RaftState {
        RaftState {
            this_id: uuid,
            state_directory: state_dir,
            current_term: Term::new(0),
            voted_for: None,
            log: Vec::new(),
            commit_index: 0,
            last_applied: 0,
            role: Role::Follower,
        }
    }
}
