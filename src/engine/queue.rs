use crate::model::CandidateValue;
use std::collections::HashSet;

pub struct Visited {
    seen: HashSet<CandidateValue>,
}

impl Visited {
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }

    pub fn insert_new(&mut self, v: &CandidateValue) -> bool {
        self.seen.insert(v.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CandidateValue;

    #[test]
    fn dedups() {
        let mut v = Visited::new();
        let h = CandidateValue::Host("dev.example.com".into());
        assert!(v.insert_new(&h));
        assert!(!v.insert_new(&h));
    }
}
