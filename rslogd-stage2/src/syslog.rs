use chrono::prelude::*;
use std::net::SocketAddr;

#[derive(Debug)]
pub struct SyslogMsg {
    from: SocketAddr,
    facility: u8,
    severity: u8,
    version: u8,
    timestamp: DateTime<Utc>,
    hostname: String,
    msg: String,
}

trait SliceExt {
    fn slice_until_space(&self) -> &Self;
    fn slice_between_arrows(&self) -> &Self;
}

impl SliceExt for [u8] {
    fn slice_until_space(&self) -> &[u8] {
        fn is_whitespace(c: &u8) -> bool {
            *c == b' '
        }

        fn is_not_whitespace(c: &u8) -> bool {
            !is_whitespace(c)
        }

        if let Some(first) = self.iter().position(is_not_whitespace) {
            if let Some(space) = self.iter().position(is_whitespace) {
                &self[first..space]
            } else {
                &self[first..]
            }
        } else {
            &[]
        }
    }

    fn slice_between_arrows(&self) -> &[u8] {
        fn is_left_arrow(c: &u8) -> bool {
            *c == b'<'
        }

        fn is_right_arrow(c: &u8) -> bool {
            *c == b'>'
        }

        if let Some(left) = self.iter().position(is_left_arrow) {
            if let Some(right) = self.iter().position(is_right_arrow) {
                &self[left..right + 1]
            } else {
                &[]
            }
        } else {
            &[]
        }
    }
}

fn syslog_parse_pri(pri_with_arrows: &[u8]) -> Option<(u8, u8)> {
    let len = pri_with_arrows.len();
    if len < 3 || len > 5 {
        return None;
    }
    let pri_str = String::from_utf8(pri_with_arrows[1..len - 1].to_vec()).unwrap();
    let num: i32 = pri_str.parse().unwrap();
    let facility = num / 8;
    let severity = num % 8;
    Some((facility as u8, severity as u8))
}

// In old BSD syle, a three letter abreviation of the month capitalized follows the priority. Test for this.
fn syslog_bsd_style(month: &str) -> bool {
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    months.contains(&month)
}

// decode packet
pub fn parse(from: SocketAddr, len: usize, buf: &[u8]) -> Option<SyslogMsg> {
    let mut first = 0;
    let pri_str = buf[first..len].slice_between_arrows();
    let (facility, severity) = match syslog_parse_pri(pri_str) {
        Some((f, s)) => (f, s),
        None => {
            println!(
                "rslogd: error decoding pri: {:?}",
                String::from_utf8(buf[0..len].to_vec())
            );
            return None;
        }
    };
    let pri_len = pri_str.len();
    first += pri_len;

    if syslog_bsd_style(&String::from_utf8(buf[first..first + 3].to_vec()).unwrap()) {
        let local: DateTime<Local> = Local::now();
        let ts = format!(
            "{} {}",
            local.format("%z %Y"),
            String::from_utf8(buf[first..first + 15].to_vec()).unwrap()
        );
        first += 15;
        let timestamp = DateTime::parse_from_str(&ts, "%z %Y %b %e %H:%M:%S").expect(&ts);

        while buf[first] == b' ' {
            first += 1;
        }
        let hostname = String::from_utf8(buf[first..len].slice_until_space().to_vec()).unwrap();
        let hlen = hostname.len();
        first += hlen;

        while buf[first] == b' ' {
            first += 1;
        }
        let msg = String::from_utf8(buf[first..len].to_vec()).unwrap();

        Some(SyslogMsg {
            from: from,
            facility: facility,
            severity: severity,
            version: 0,
            timestamp: timestamp.with_timezone(&Utc),
            hostname: hostname,
            msg: msg,
        })
    } else {
        // assume RFC 5424 format
        let vstring = String::from_utf8(buf[first..len].slice_until_space().to_vec()).unwrap();
        let vlen = vstring.len();
        first += vlen;
        let version = vstring.parse::<u8>().expect("version parse");

        while buf[first] == b' ' {
            first += 1;
        }
        Some(SyslogMsg {
            from: from,
            facility: facility,
            severity: severity,
            version: version,
            timestamp: Utc::now(),
            hostname: "na".to_string(),
            msg: "na".to_string(),
        })
    }
}
