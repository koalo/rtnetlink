// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;
use netlink_packet_core::{
    NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST,
};
use netlink_packet_route::{
    tc::{
        TaprioScheduleEntry, TaprioScheduleEntryItem, TaprioTcEntry,
        TcAttribute, TcHandle, TcMessage, TcOption,
        TcPriomap, TcQdiscTaprioOption,
    },
    RouteNetlinkMessage,
};

use crate::{try_nl, Error, Handle};

pub struct QDiscNewRequest {
    handle: Handle,
    message: TcMessage,
    flags: u16,
}

impl QDiscNewRequest {
    pub(crate) fn new(handle: Handle, message: TcMessage, flags: u16) -> Self {
        Self {
            handle,
            message,
            flags: NLM_F_REQUEST | flags,
        }
    }

    /// Execute the request
    pub async fn execute(self) -> Result<(), Error> {
        let Self {
            mut handle,
            message,
            flags,
        } = self;

        let mut req = NetlinkMessage::from(
            RouteNetlinkMessage::NewQueueDiscipline(message),
        );
        req.header.flags = NLM_F_ACK | flags;

        let mut response = handle.request(req)?;
        while let Some(message) = response.next().await {
            try_nl!(message);
        }
        Ok(())
    }

    /// Set handle,
    pub fn handle(mut self, major: u16, minor: u16) -> Self {
        self.message.header.handle = TcHandle { major, minor };
        self
    }

    /// Set parent to root.
    pub fn root(mut self) -> Self {
        self.message.header.parent = TcHandle::ROOT;
        self
    }

    /// Set parent
    pub fn parent(mut self, parent: u32) -> Self {
        self.message.header.parent = parent.into();
        self
    }

    /// New a ingress qdisc
    pub fn ingress(mut self) -> Self {
        self.message.header.parent = TcHandle::INGRESS;
        self.message.header.handle = TcHandle::from(0xffff0000);
        self.message
            .attributes
            .push(TcAttribute::Kind("ingress".to_string()));
        self
    }

    /// New taprio qdisc
    pub fn taprio(mut self) -> QDiscTaprioNewRequest {
        self.message
            .attributes
            .push(TcAttribute::Kind("taprio".to_string()));
        QDiscTaprioNewRequest::new(self)
    }
}

pub struct QDiscTaprioNewRequest {
    request: QDiscNewRequest,
    options: Vec<TcOption>,
    priomap: TcPriomap,
    tc_entries: Vec<Vec<TaprioTcEntry>>,
}

impl QDiscTaprioNewRequest {
    pub(crate) fn new(request: QDiscNewRequest) -> Self {
        Self {
            request,
            options: vec![],
            priomap: TcPriomap::default(),
            tc_entries: vec![],
        }
    }

    /// Execute the request
    pub async fn execute(mut self) -> Result<(), Error> {
        if self
            .priomap
            .prio_tc_map
            .iter()
            .any(|&x| x >= self.priomap.num_tc)
        {
            return Err(Error::InvalidNla("All values in the prio to tc map need to be smaller than num_tc".to_string()));
        }

        self.options
            .push(TcOption::Taprio(TcQdiscTaprioOption::Priomap(self.priomap)));

        self.options.extend(self.tc_entries.iter().map(|entry| {
            TcOption::Taprio(TcQdiscTaprioOption::Tc(entry.to_vec()))
        }));

        self.request
            .message
            .attributes
            .push(TcAttribute::Options(self.options));

        self.request.execute().await
    }

    /// Set clockid
    pub fn clockid(mut self, clock_id: u32) -> Self {
        self.options
            .push(TcOption::Taprio(TcQdiscTaprioOption::ClockId(clock_id)));
        self
    }

    /// Set flags
    pub fn flags(mut self, flags: u32) -> Self {
        self.options
            .push(TcOption::Taprio(TcQdiscTaprioOption::Flags(flags)));
        self
    }

    /// Set num_tc
    pub fn num_tc(mut self, num_tc: u8) -> Self {
        self.priomap.num_tc = num_tc;
        self
    }

    /// Set priority to tc map
    pub fn priority_map(mut self, map: Vec<u8>) -> Result<Self, Error> {
        let len = map.len();

        if len > 16 {
            return Err(Error::InvalidNla("No more than 16 elements are allowed in the priority to tc map".to_string()));
        }

        self.priomap.prio_tc_map[..len].copy_from_slice(&map[..len]);

        // Fill remaining elements with 0
        for elem in &mut self.priomap.prio_tc_map[len..] {
            *elem = 0;
        }

        Ok(self)
    }

    /// Set queues as pairs of count and offset for each traffic class
    /// Queue ranges for each traffic classes cannot overlap
    /// and must be a contiguous range of queues.
    pub fn queues(mut self, queues: Vec<(u16, u16)>) -> Result<Self, Error> {
        let len = queues.len();

        if len > 16 {
            return Err(Error::InvalidNla(
                "No more than 16 elements are allowed in the queue list"
                    .to_string(),
            ));
        }

        for (index, &(c, o)) in queues.iter().enumerate().take(16) {
            self.priomap.count[index] = c;
            self.priomap.offset[index] = o;
        }

        // Fill remaining elements with 0
        for index in len..16 {
            self.priomap.count[index] = 0;
            self.priomap.offset[index] = 0;
        }

        Ok(self)
    }

    /// Set txtime delay
    pub fn txtime_delay(mut self, delay: u32) -> Self {
        self.options
            .push(TcOption::Taprio(TcQdiscTaprioOption::TxtimeDelay(delay)));
        self
    }

    /// Set basetime
    pub fn basetime(mut self, basetime: i64) -> Self {
        self.options
            .push(TcOption::Taprio(TcQdiscTaprioOption::Basetime(basetime)));
        self
    }

    /// Set cycletime
    pub fn cycletime(mut self, cycletime: i64) -> Self {
        self.options
            .push(TcOption::Taprio(TcQdiscTaprioOption::Cycletime(cycletime)));
        self
    }

    /// Set cycletime extension
    pub fn cycletime_extension(mut self, cycletime_extension: i64) -> Self {
        self.options.push(TcOption::Taprio(
            TcQdiscTaprioOption::CycletimeExtension(cycletime_extension),
        ));
        self
    }

    /// Set max_sdu values for each traffic class
    /// The value 0 means that the traffic class can send packets up
    /// to the port's maximum MTU in size.
    pub fn max_sdu(mut self, max_sdu: Vec<u32>) -> Self {
        for (index, value) in (0..16 as u8).zip(max_sdu.into_iter()) {
            if usize::from(index) >= self.tc_entries.len() {
                self.tc_entries
                    .push(vec![TaprioTcEntry::Index(index.into())]);
            }

            self.tc_entries[usize::from(index)]
                .push(TaprioTcEntry::MaxSdu(value));
        }

        self
    }

    /// Set fp values for each traffic class
    /// Use E for express and P for preemptible (according to IEEE 802.1Q-2018 clause 6.7.2)
    pub fn fp(mut self, fp: Vec<char>) -> Result<Self, Error> {
        for (index, value) in (0..16 as u8).zip(fp.into_iter()) {
            if usize::from(index) >= self.tc_entries.len() {
                self.tc_entries
                    .push(vec![TaprioTcEntry::Index(index.into())]);
            }

            self.tc_entries[usize::from(index)].push(
                TaprioTcEntry::fp_from_char(value)
                    .map_err(|e| Error::InvalidNla(e.to_string()))?,
            );
        }

        Ok(self)
    }

    /// Set schedule as 3-tuples with (cmd, gate_mask, interval)
    pub fn schedule(
        mut self,
        schedule: Vec<(char, u32, u32)>,
    ) -> Result<Self, Error> {
        self.options
            .push(TcOption::Taprio(TcQdiscTaprioOption::Schedule(
                schedule
                    .iter()
                    .map(|(cmd, gate_mask, interval)| {
                        Ok(TaprioScheduleEntry::Entry(vec![
                            TaprioScheduleEntryItem::cmd_from_char(*cmd)
                                .map_err(|e| {
                                    Error::InvalidNla(e.to_string())
                                })?,
                            TaprioScheduleEntryItem::GateMask(*gate_mask),
                            TaprioScheduleEntryItem::Interval(*interval),
                        ]))
                    })
                    .collect::<Result<Vec<TaprioScheduleEntry>, Error>>()?,
            )));

        Ok(self)
    }
}

#[cfg(test)]
mod test {
    use std::{fs::File, os::fd::AsFd, path::Path};

    use futures::stream::TryStreamExt;
    use nix::sched::{setns, CloneFlags};
    use tokio::runtime::Runtime;

    use super::*;
    use crate::{new_connection, NetworkNamespace, NETNS_PATH, SELF_NS_PATH, Error::NetlinkError};
    use netlink_packet_route::{
        link::LinkMessage, tc::{TcAttribute, TcHeader, TcMessageBuffer}, AddressFamily,
    };

    use netlink_packet_utils::traits::Parseable;

    const TEST_NS: &str = "netlink_test_qdisc_ns";
    const TEST_NS_TAPRIO: &str = "netlink_test_taprio_qdisc_ns";
    const TEST_DUMMY: &str = "test_dummy";

    struct Netns {
        path: String,
        _cur: File,
        last: File,
    }

    impl Netns {
        async fn new(path: &str) -> Self {
            // record current ns
            let last = File::open(Path::new(SELF_NS_PATH)).unwrap();

            // create new ns
            NetworkNamespace::add(path.to_string()).await.unwrap();

            // entry new ns
            let ns_path = Path::new(NETNS_PATH);
            let file = File::open(ns_path.join(path)).unwrap();
            setns(file.as_fd(), CloneFlags::CLONE_NEWNET).unwrap();

            Self {
                path: path.to_string(),
                _cur: file,
                last,
            }
        }
    }
    impl Drop for Netns {
        fn drop(&mut self) {
            println!("exit ns: {}", self.path);
            setns(self.last.as_fd(), CloneFlags::CLONE_NEWNET).unwrap();

            let ns_path = Path::new(NETNS_PATH).join(&self.path);
            nix::mount::umount2(&ns_path, nix::mount::MntFlags::MNT_DETACH)
                .unwrap();
            nix::unistd::unlink(&ns_path).unwrap();
            // _cur File will be closed auto
            // Since there is no async drop, NetworkNamespace::del cannot be
            // called here. Dummy interface will be deleted
            // automatically after netns is deleted.
        }
    }

    async fn setup_env(path: &str) -> (Handle, LinkMessage, Netns) {
        let netns = Netns::new(path).await;

        // Notice: The Handle can only be created after the setns, so that the
        // Handle is the connection within the new ns.
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        handle
            .link()
            .add()
            .dummy(TEST_DUMMY.to_string())
            .execute()
            .await
            .unwrap();
        let mut links = handle
            .link()
            .get()
            .match_name(TEST_DUMMY.to_string())
            .execute();
        let link = links.try_next().await.unwrap();
        (handle, link.unwrap(), netns)
    }

    async fn test_async_new_qdisc() {
        let (handle, test_link, _netns) = setup_env(TEST_NS).await;
        handle
            .qdisc()
            .add(test_link.header.index as i32)
            .ingress()
            .execute()
            .await
            .unwrap();
        let mut qdiscs_iter = handle
            .qdisc()
            .get()
            .index(test_link.header.index as i32)
            .ingress()
            .execute();

        let mut found = false;
        while let Some(nl_msg) = qdiscs_iter.try_next().await.unwrap() {
            if nl_msg.header.index == test_link.header.index as i32
                && nl_msg.header.handle == 0xffff0000.into()
            {
                assert_eq!(nl_msg.header.family, AddressFamily::Unspec);
                assert_eq!(nl_msg.header.handle, 0xffff0000.into());
                assert_eq!(nl_msg.header.parent, TcHandle::INGRESS);
                assert_eq!(nl_msg.header.info, 1); // refcount
                assert_eq!(
                    nl_msg.attributes[0],
                    TcAttribute::Kind("ingress".to_string())
                );
                assert_eq!(nl_msg.attributes[2], TcAttribute::HwOffload(0));
                found = true;
                break;
            }
        }
        if !found {
            panic!("not found dev:{} qdisc.", test_link.header.index);
        }
    }

    #[test]
    fn test_new_qdisc() {
        Runtime::new().unwrap().block_on(test_async_new_qdisc());
    }

    async fn test_async_new_taprio_qdisc() {
        let (handle, test_link, _netns) = setup_env(TEST_NS_TAPRIO).await;

        // We know this will fail, because to succeed we would need a
        // TAPRIO-capable interface. Still, we can test if all the parsing
        // is correct and if it matches the expected message.

        let result = handle
            .qdisc()
            .add(test_link.header.index as i32)
            .taprio()
            .clockid(11)
            .flags(0x1)
            .num_tc(3)
            .priority_map(vec![2, 2, 1, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2])
            .unwrap()
            .queues(vec![(1, 0), (1, 1), (1, 2)])
            .unwrap()
            .txtime_delay(500000)
            .basetime(1000000000)
            .cycletime(1000000)
            .cycletime_extension(100)
            .max_sdu(vec![0, 300, 200])
            .fp(vec!['P', 'E', 'E', 'P'])
            .unwrap()
            .schedule(vec![
                ('S', 0x1, 300000),
                ('S', 0x3, 300000),
                ('S', 0x4, 400000),
            ])
            .unwrap()
            .execute()
            .await
            .expect_err("taprio is not expected to work for dummy interface");

        let expected = TcMessage::from_parts(
            TcHeader {
                family: AddressFamily::Unspec,
                index: 2,
                handle: TcHandle::UNSPEC,
                parent: TcHandle::UNSPEC,
                info: 0,
            },
            vec![
                TcAttribute::Kind("taprio".to_string()),
                TcAttribute::Options(vec![
                    TcOption::Taprio(TcQdiscTaprioOption::ClockId(11)),
                    TcOption::Taprio(TcQdiscTaprioOption::Flags(0x1)),
                    TcOption::Taprio(TcQdiscTaprioOption::TxtimeDelay(500000)),
                    TcOption::Taprio(TcQdiscTaprioOption::Basetime(1000000000)),
                    TcOption::Taprio(TcQdiscTaprioOption::Cycletime(1000000)),
                    TcOption::Taprio(TcQdiscTaprioOption::CycletimeExtension(
                        100,
                    )),
                    TcOption::Taprio(TcQdiscTaprioOption::Schedule(vec![
                        TaprioScheduleEntry::Entry(vec![
                            TaprioScheduleEntryItem::cmd_from_char('S')
                                .unwrap(),
                            TaprioScheduleEntryItem::GateMask(0x1),
                            TaprioScheduleEntryItem::Interval(300000),
                        ]),
                        TaprioScheduleEntry::Entry(vec![
                            TaprioScheduleEntryItem::cmd_from_char('S')
                                .unwrap(),
                            TaprioScheduleEntryItem::GateMask(0x3),
                            TaprioScheduleEntryItem::Interval(300000),
                        ]),
                        TaprioScheduleEntry::Entry(vec![
                            TaprioScheduleEntryItem::cmd_from_char('S')
                                .unwrap(),
                            TaprioScheduleEntryItem::GateMask(0x4),
                            TaprioScheduleEntryItem::Interval(400000),
                        ]),
                    ])),
                    TcOption::Taprio(TcQdiscTaprioOption::Priomap(
                        TcPriomap::from_parts(
                            3,
                            [2, 2, 1, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
                            0,
                            [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                            [0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        ),
                    )),
                    TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                        TaprioTcEntry::Index(0),
                        TaprioTcEntry::MaxSdu(0),
                        TaprioTcEntry::fp_from_char('P').unwrap(),
                    ])),
                    TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                        TaprioTcEntry::Index(1),
                        TaprioTcEntry::MaxSdu(300),
                        TaprioTcEntry::fp_from_char('E').unwrap(),
                    ])),
                    TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                        TaprioTcEntry::Index(2),
                        TaprioTcEntry::MaxSdu(200),
                        TaprioTcEntry::fp_from_char('E').unwrap(),
                    ])),
                    TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                        TaprioTcEntry::Index(3),
                        TaprioTcEntry::fp_from_char('P').unwrap(),
                    ])),
                ]),
            ],
        );

        if let NetlinkError(mut error) = result {
            assert_eq!(error.code.unwrap().get(), -22);

            let message = TcMessage::parse(&TcMessageBuffer::new(
                &error.header.split_off(16),
            ))
            .unwrap();

            assert_eq!(expected, message);
        } else {
            panic!("Wrong error type");
        }
    }

    #[test]
    fn test_new_taprio_qdisc() {
        Runtime::new()
            .unwrap()
            .block_on(test_async_new_taprio_qdisc());
    }
}
