use futures::{Async, Poll, Stream};

/// An adapter for merging the output of two streams.
///
/// The merged stream produces items from either of the underlying streams as
/// they become available, and the streams are polled in a round-robin fashion.
/// Errors, however, are not merged: you get at most one error at a time.
///
/// Based on the Select adapter from the futures crate.
///
/// Copyright (c) 2016 Alex Crichton
/// Copyright (c) 2018 The Ire Developers
pub(super) struct Select<'a, S1: 'a, S2: 'a> {
    pub(super) stream1: &'a mut S1,
    pub(super) stream2: &'a mut S2,
    pub(super) flag: &'a mut bool,
}

impl<'a, S1, S2> Stream for Select<'a, S1, S2>
where
    S1: Stream,
    S2: Stream<Item = S1::Item, Error = S1::Error>,
{
    type Item = S1::Item;
    type Error = S1::Error;

    fn poll(&mut self) -> Poll<Option<S1::Item>, S1::Error> {
        let (a, b) = if *self.flag {
            (
                &mut self.stream2 as &mut Stream<Item = _, Error = _>,
                &mut self.stream1 as &mut Stream<Item = _, Error = _>,
            )
        } else {
            (
                &mut self.stream1 as &mut Stream<Item = _, Error = _>,
                &mut self.stream2 as &mut Stream<Item = _, Error = _>,
            )
        };
        *self.flag = !*self.flag;

        let a_done = match a.poll()? {
            Async::Ready(Some(item)) => return Ok(Some(item).into()),
            Async::Ready(None) => true,
            Async::NotReady => false,
        };

        match b.poll()? {
            Async::Ready(Some(item)) => {
                // If the other stream isn't finished yet, give them a chance to
                // go first next time as we pulled something off `b`.
                if !a_done {
                    *self.flag = !*self.flag;
                }
                Ok(Some(item).into())
            }
            Async::Ready(None) if a_done => Ok(None.into()),
            Async::Ready(None) | Async::NotReady => Ok(Async::NotReady),
        }
    }
}
