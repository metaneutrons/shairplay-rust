//! Limiting the mDNS announcement to chosen network interfaces.
//!
//! The caller names the addresses its listeners use, the server resolves them to
//! interfaces and refuses to start when it cannot. It never falls back to announcing
//! on every interface.

use std::net::IpAddr;

use crate::error::NetworkError;

/// Where the AirPlay mDNS announcement is sent.
///
/// The default is [`MdnsScope::All`], which announces on every interface of the host.
///
/// # Examples
/// ```
/// use shairplay::MdnsScope;
///
/// // Announce only on the interface that carries 192.168.1.10.
/// let scope = MdnsScope::Addrs(vec!["192.168.1.10".parse().unwrap()]);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum MdnsScope {
    /// Announce on every interface of the host.
    #[default]
    All,
    /// Announce only on the interfaces that carry these addresses.
    ///
    /// The list must not be empty and must not contain an unspecified address
    /// (`0.0.0.0`, `::`). Every address must belong to an interface of this host,
    /// otherwise [`RaopServer::start`](crate::RaopServer::start) fails.
    ///
    /// The address selects the interface, not the single address: other addresses on
    /// the same interface are announced as well.
    Addrs(Vec<IpAddr>),
}

impl MdnsScope {
    /// Limit the announcement to the interfaces that carry the addresses of `bind`.
    ///
    /// A [`BindConfig`](crate::BindConfig) without addresses binds to every interface,
    /// so it yields [`MdnsScope::All`].
    pub fn from_bind(bind: &crate::BindConfig) -> Self {
        if bind.bind_addrs.is_empty() {
            Self::All
        } else {
            Self::Addrs(bind.bind_addrs.clone())
        }
    }
}

/// What the server did with the requested [`MdnsScope`].
///
/// Read it with [`RaopServer::mdns_scope_applied`](crate::RaopServer::mdns_scope_applied)
/// after `start()`, to log the result or to refuse to run.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MdnsScopeApplied {
    /// The announcement goes out on every interface, as requested.
    All,
    /// The announcement is limited to these interfaces (by name).
    ///
    /// Other addresses of the same interfaces are still announced.
    Interfaces(Vec<String>),
    /// A limit was requested, but this platform cannot apply it. The announcement
    /// goes out on every interface.
    Unsupported,
}

/// One address of the host, as read from the interface table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostAddr {
    pub(crate) name: String,
    pub(crate) ip: IpAddr,
}

/// A validated scope: the requested addresses and the interfaces they live on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopePlan {
    pub(crate) addrs: Vec<IpAddr>,
    pub(crate) interfaces: Vec<String>,
}

/// Validate `scope` against the interface table of this host.
///
/// Returns `None` for [`MdnsScope::All`].
pub(crate) fn plan(scope: &MdnsScope) -> Result<Option<ScopePlan>, NetworkError> {
    let MdnsScope::Addrs(addrs) = scope else {
        return Ok(None);
    };
    let table: Vec<HostAddr> = if_addrs::get_if_addrs()?
        .into_iter()
        .map(|i| HostAddr {
            ip: i.ip(),
            name: i.name,
        })
        .collect();
    plan_with(addrs, &table).map(Some)
}

/// [`plan`] against a given interface table.
pub(crate) fn plan_with(addrs: &[IpAddr], table: &[HostAddr]) -> Result<ScopePlan, NetworkError> {
    if addrs.is_empty() {
        return Err(scope_error("the address list is empty"));
    }
    let mut unique: Vec<IpAddr> = Vec::new();
    let mut interfaces: Vec<String> = Vec::new();
    for addr in addrs {
        if addr.is_unspecified() {
            return Err(scope_error(&format!(
                "{addr} is a wildcard address and selects no interface"
            )));
        }
        let Some(host) = table.iter().find(|h| h.ip == *addr) else {
            return Err(scope_error(&format!(
                "{addr} is not an address of any interface of this host"
            )));
        };
        if !unique.contains(addr) {
            unique.push(*addr);
        }
        if !interfaces.contains(&host.name) {
            interfaces.push(host.name.clone());
        }
    }
    Ok(ScopePlan {
        addrs: unique,
        interfaces,
    })
}

fn scope_error(reason: &str) -> NetworkError {
    NetworkError::Mdns(format!("mDNS scope: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str, ip: &str) -> HostAddr {
        HostAddr {
            name: name.into(),
            ip: ip.parse().unwrap(),
        }
    }

    fn table() -> Vec<HostAddr> {
        vec![
            host("lo", "127.0.0.1"),
            host("lo", "::1"),
            host("eth0", "192.168.1.10"),
            host("eth0", "fe80::1"),
            host("eth0", "fd00::10"),
            host("nebula1", "10.77.0.5"),
        ]
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn all_needs_no_plan() {
        assert_eq!(plan(&MdnsScope::All).unwrap(), None);
    }

    #[test]
    fn default_scope_is_all() {
        assert_eq!(MdnsScope::default(), MdnsScope::All);
    }

    #[test]
    fn one_address_selects_its_interface() {
        let p = plan_with(&ips(&["192.168.1.10"]), &table()).unwrap();
        assert_eq!(p.addrs, ips(&["192.168.1.10"]));
        assert_eq!(p.interfaces, ["eth0"]);
    }

    #[test]
    fn two_addresses_of_one_interface_name_it_once() {
        let p = plan_with(&ips(&["192.168.1.10", "fd00::10"]), &table()).unwrap();
        assert_eq!(p.addrs.len(), 2);
        assert_eq!(p.interfaces, ["eth0"]);
    }

    #[test]
    fn addresses_of_two_interfaces_name_both() {
        let p = plan_with(&ips(&["10.77.0.5", "192.168.1.10"]), &table()).unwrap();
        assert_eq!(p.interfaces, ["nebula1", "eth0"]);
    }

    #[test]
    fn duplicate_addresses_are_collapsed() {
        let p = plan_with(&ips(&["192.168.1.10", "192.168.1.10"]), &table()).unwrap();
        assert_eq!(p.addrs, ips(&["192.168.1.10"]));
    }

    #[test]
    fn link_local_ipv6_and_loopback_resolve() {
        let p = plan_with(&ips(&["fe80::1", "127.0.0.1"]), &table()).unwrap();
        assert_eq!(p.interfaces, ["eth0", "lo"]);
    }

    #[test]
    fn empty_list_is_refused() {
        assert!(plan_with(&[], &table()).is_err());
    }

    #[test]
    fn wildcards_are_refused() {
        assert!(plan_with(&ips(&["0.0.0.0"]), &table()).is_err());
        assert!(plan_with(&ips(&["::"]), &table()).is_err());
        assert!(plan_with(&ips(&["192.168.1.10", "::"]), &table()).is_err());
    }

    #[test]
    fn unknown_address_is_refused_even_next_to_a_known_one() {
        let err = plan_with(&ips(&["192.168.1.10", "172.16.0.9"]), &table()).unwrap_err();
        assert!(err.to_string().contains("172.16.0.9"), "{err}");
    }

    #[test]
    fn from_bind_follows_the_addresses() {
        let none = crate::BindConfig::new();
        assert_eq!(MdnsScope::from_bind(&none), MdnsScope::All);
        let some = crate::BindConfig::new().addrs(ips(&["192.168.1.10"]));
        assert_eq!(
            MdnsScope::from_bind(&some),
            MdnsScope::Addrs(ips(&["192.168.1.10"]))
        );
    }

    #[test]
    fn this_host_resolves_its_own_loopback() {
        // Loopback exists on every host this runs on.
        let scope = MdnsScope::Addrs(ips(&["127.0.0.1"]));
        let p = plan(&scope).unwrap().unwrap();
        assert_eq!(p.addrs, ips(&["127.0.0.1"]));
        assert_eq!(p.interfaces.len(), 1);
    }
}
