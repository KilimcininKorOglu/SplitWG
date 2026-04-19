//! Evaluator that maps the current `NetState` + a tunnel's `OnDemandRule`
//! to a desired action (`Connect`, `Disconnect`, `Untouched`).
//!
//! The rule itself lives in `config::OnDemandRule`; this module owns only
//! the decision logic so the evaluator stays test-friendly.

use crate::config::OnDemandRule;

/// Snapshot of the current network, produced by `gui::network_monitor`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetState {
    /// Wi-Fi SSID if the system reports one (empty → not on Wi-Fi or
    /// Location Services not authorised).
    pub active_ssid: Option<String>,
    /// `true` when the default route goes through a wired interface.
    pub wired_up: bool,
    /// `true` when the default route goes through a Wi-Fi interface.
    pub wifi_up: bool,
    /// Current local wall-clock snapshot used for schedule evaluation.
    /// `None` = monitor hasn't produced a sample yet; schedule checks
    /// are skipped (preserves legacy behaviour for tests and early boot).
    pub local_time: Option<LocalTime>,
}

/// Compact local-time snapshot consumed by the schedule evaluator.
/// `weekday`: 0 = Monday … 6 = Sunday (matches `ScheduleRule.weekdays_mask`
/// bit order). `hour`: 0..=23.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTime {
    pub weekday: u8,
    pub hour: u8,
}

/// Outcome of evaluating a rule — the caller turns this into a
/// `mgr.connect` / `mgr.disconnect` call when the tunnel is not under
/// manual override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Desired {
    Connect,
    Disconnect,
    Untouched,
}

/// Returns the desired action for a tunnel given its rule and the current
/// network. When the rule has no active criteria (everything empty/false)
/// the result is `Untouched` so the monitor never nukes a user's manual
/// state just because they turned the feature on and left it blank.
pub fn decide(rule: &OnDemandRule, state: &NetState) -> Desired {
    let has_any_criterion = rule.always
        || rule.activate_on_ethernet
        || rule.activate_on_wifi
        || !rule.trusted_ssids.is_empty()
        || !rule.untrusted_ssids.is_empty()
        || rule.schedule.is_some();
    if !has_any_criterion {
        log::info!("splitwg: on_demand: no criteria set, returning Untouched");
        return Desired::Untouched;
    }

    if let (Some(sched), Some(now)) = (rule.schedule.as_ref(), state.local_time) {
        if !in_schedule(sched, now) {
            log::info!("splitwg: on_demand: outside schedule window -> Disconnect");
            return Desired::Disconnect;
        }
    }

    if let Some(ssid) = state.active_ssid.as_deref() {
        if rule
            .untrusted_ssids
            .iter()
            .any(|s| s.eq_ignore_ascii_case(ssid))
        {
            log::info!("splitwg: on_demand: SSID {:?} is untrusted -> Disconnect", ssid);
            return Desired::Disconnect;
        }
        if rule
            .trusted_ssids
            .iter()
            .any(|s| s.eq_ignore_ascii_case(ssid))
        {
            log::info!("splitwg: on_demand: SSID {:?} is trusted -> Connect", ssid);
            return Desired::Connect;
        }
    }

    if rule.always {
        log::info!("splitwg: on_demand: always flag set -> Connect");
        return Desired::Connect;
    }
    if rule.activate_on_ethernet && state.wired_up {
        log::info!("splitwg: on_demand: activate_on_ethernet matched -> Connect");
        return Desired::Connect;
    }
    if rule.activate_on_wifi && state.wifi_up {
        log::info!("splitwg: on_demand: activate_on_wifi matched -> Connect");
        return Desired::Connect;
    }

    log::info!("splitwg: on_demand: no criteria matched -> Disconnect");
    Desired::Disconnect
}

/// Pure schedule check — returns `true` when `now` falls within the
/// rule's weekday mask AND hour window. `hour_start == hour_end` is
/// treated as an all-day window; `hour_start > hour_end` wraps midnight.
fn in_schedule(sched: &crate::config::ScheduleRule, now: LocalTime) -> bool {
    if now.weekday > 6 {
        return false;
    }
    let day_bit = 1u8 << now.weekday;
    if sched.weekdays_mask & day_bit == 0 {
        return false;
    }
    let hs = sched.hour_start;
    let he = sched.hour_end;
    if hs == he {
        return true;
    }
    if hs < he {
        now.hour >= hs && now.hour < he
    } else {
        now.hour >= hs || now.hour < he
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScheduleRule;

    fn rule() -> OnDemandRule {
        OnDemandRule::default()
    }

    fn net_wifi(ssid: &str) -> NetState {
        NetState {
            active_ssid: Some(ssid.into()),
            wired_up: false,
            wifi_up: true,
            local_time: None,
        }
    }

    #[test]
    fn empty_rule_is_untouched() {
        assert_eq!(decide(&rule(), &NetState::default()), Desired::Untouched);
    }

    #[test]
    fn always_connects_regardless_of_network() {
        let r = OnDemandRule { always: true, ..Default::default() };
        assert_eq!(decide(&r, &NetState::default()), Desired::Connect);
    }

    #[test]
    fn trusted_ssid_connects() {
        let r = OnDemandRule {
            trusted_ssids: vec!["home".into()],
            ..Default::default()
        };
        assert_eq!(decide(&r, &net_wifi("home")), Desired::Connect);
    }

    #[test]
    fn untrusted_ssid_disconnects_over_trusted() {
        let r = OnDemandRule {
            trusted_ssids: vec!["home".into()],
            untrusted_ssids: vec!["home".into()],
            always: true,
            ..Default::default()
        };
        // Untrusted match short-circuits even when `always` is set.
        assert_eq!(decide(&r, &net_wifi("home")), Desired::Disconnect);
    }

    #[test]
    fn activate_on_wifi_but_no_ssid_disconnects() {
        let r = OnDemandRule {
            activate_on_wifi: true,
            ..Default::default()
        };
        assert_eq!(decide(&r, &NetState::default()), Desired::Disconnect);
    }

    #[test]
    fn activate_on_ethernet_matches_wired() {
        let r = OnDemandRule {
            activate_on_ethernet: true,
            ..Default::default()
        };
        let state = NetState {
            active_ssid: None,
            wired_up: true,
            wifi_up: false,
            local_time: None,
        };
        assert_eq!(decide(&r, &state), Desired::Connect);
    }

    #[test]
    fn ssid_match_is_case_insensitive() {
        let r = OnDemandRule {
            trusted_ssids: vec!["Home-5G".into()],
            ..Default::default()
        };
        assert_eq!(decide(&r, &net_wifi("home-5g")), Desired::Connect);
    }

    fn schedule(mask: u8, hs: u8, he: u8) -> ScheduleRule {
        ScheduleRule {
            weekdays_mask: mask,
            hour_start: hs,
            hour_end: he,
        }
    }

    fn net_with_time(wd: u8, hr: u8) -> NetState {
        NetState {
            active_ssid: None,
            wired_up: true,
            wifi_up: false,
            local_time: Some(LocalTime {
                weekday: wd,
                hour: hr,
            }),
        }
    }

    #[test]
    fn schedule_none_keeps_legacy_behaviour() {
        let r = OnDemandRule {
            always: true,
            ..Default::default()
        };
        // No schedule, no local_time — still Connect.
        assert_eq!(decide(&r, &NetState::default()), Desired::Connect);
    }

    #[test]
    fn schedule_weekdays_09_to_18_tuesday_morning_connects() {
        let r = OnDemandRule {
            always: true,
            schedule: Some(schedule(0b0011111, 9, 18)),
            ..Default::default()
        };
        // Weekday=1 (Tuesday), hour=10 → inside.
        assert_eq!(decide(&r, &net_with_time(1, 10)), Desired::Connect);
    }

    #[test]
    fn schedule_weekdays_09_to_18_tuesday_evening_disconnects() {
        let r = OnDemandRule {
            always: true,
            schedule: Some(schedule(0b0011111, 9, 18)),
            ..Default::default()
        };
        // Weekday=1 (Tuesday), hour=20 → outside.
        assert_eq!(decide(&r, &net_with_time(1, 20)), Desired::Disconnect);
    }

    #[test]
    fn schedule_weekend_day_disconnects() {
        let r = OnDemandRule {
            always: true,
            schedule: Some(schedule(0b0011111, 9, 18)),
            ..Default::default()
        };
        // Saturday (5), during hour window but disallowed weekday.
        assert_eq!(decide(&r, &net_with_time(5, 10)), Desired::Disconnect);
    }

    #[test]
    fn schedule_overnight_window_wraps_midnight() {
        let r = OnDemandRule {
            always: true,
            schedule: Some(schedule(0x7F, 22, 6)),
            ..Default::default()
        };
        // 00:30 on any day → inside the overnight window.
        assert_eq!(decide(&r, &net_with_time(2, 0)), Desired::Connect);
        // 23:00 → inside.
        assert_eq!(decide(&r, &net_with_time(2, 23)), Desired::Connect);
        // 10:00 → outside.
        assert_eq!(decide(&r, &net_with_time(2, 10)), Desired::Disconnect);
    }

    #[test]
    fn schedule_mask_zero_is_treated_as_never() {
        let r = OnDemandRule {
            always: true,
            schedule: Some(schedule(0, 0, 0)),
            ..Default::default()
        };
        assert_eq!(decide(&r, &net_with_time(1, 10)), Desired::Disconnect);
    }

    #[test]
    fn schedule_all_day_when_start_equals_end() {
        let r = OnDemandRule {
            always: true,
            schedule: Some(schedule(0x7F, 7, 7)),
            ..Default::default()
        };
        assert_eq!(decide(&r, &net_with_time(3, 3)), Desired::Connect);
        assert_eq!(decide(&r, &net_with_time(3, 23)), Desired::Connect);
    }
}
