use std::cell::RefCell;
use std::rc::Rc;

use crate::mitm::flow::capture_service::FilterResourceStats;
use crate::mitm::flow::state_store::FilterStateStore;

#[derive(Debug)]
struct RuntimeStateContext {
    connection_id: String,
    filter_name: String,
    store: Option<FilterStateStore>,
    stats: RefCell<FilterResourceStats>,
}

thread_local! {
    static CURRENT_RUNTIME_STATE: RefCell<Option<Rc<RuntimeStateContext>>> = const { RefCell::new(None) };
}

pub struct RuntimeStateGuard {
    previous: Option<Rc<RuntimeStateContext>>,
    current: Rc<RuntimeStateContext>,
}

impl RuntimeStateGuard {
    pub fn enter(
        connection_id: String,
        filter_name: String,
        store: Option<FilterStateStore>,
    ) -> Self {
        let current = Rc::new(RuntimeStateContext {
            connection_id,
            filter_name,
            store,
            stats: RefCell::new(FilterResourceStats::default()),
        });

        let previous = CURRENT_RUNTIME_STATE.with(|slot| {
            let mut slot = slot.borrow_mut();
            let prev = slot.clone();
            *slot = Some(current.clone());
            prev
        });

        Self { previous, current }
    }

    pub fn finish(self) -> FilterResourceStats {
        let stats = *self.current.stats.borrow();
        CURRENT_RUNTIME_STATE.with(|slot| {
            *slot.borrow_mut() = self.previous;
        });
        stats
    }
}

fn with_context<T>(f: impl FnOnce(&RuntimeStateContext) -> T) -> Option<T> {
    CURRENT_RUNTIME_STATE.with(|slot| {
        let borrowed = slot.borrow();
        let ctx = borrowed.as_ref()?;
        Some(f(ctx))
    })
}
fn accumulate(stats: crate::mitm::flow::state_store::StateOpStats) {
    CURRENT_RUNTIME_STATE.with(|slot| {
        let borrowed = slot.borrow();
        let Some(ctx) = borrowed.as_ref() else {
            return;
        };

        let mut acc = ctx.stats.borrow_mut();
        acc.state_read_bytes += stats.read_bytes;
        acc.state_write_bytes += stats.write_bytes;
        acc.evicted_items += stats.evicted_items;
        acc.state_items = stats.state_items;
        acc.limit_hit |= stats.limit_hit;
    });
}

pub fn state_get_text(key: &str) -> Option<String> {
    with_context(|ctx| {
        let store = ctx.store.as_ref()?;

        let (value, op_stats) = store.get(&ctx.connection_id, &ctx.filter_name, key);
        accumulate(op_stats);

        value.map(|bytes| String::from_utf8_lossy(&bytes).to_string())
    })
        .flatten()
}

pub fn state_put_text(key: &str, value: &str) -> bool {
    with_context(|ctx| {
        let Some(store) = ctx.store.as_ref() else {
            return false;
        };

        let (outcome, op_stats) = store.put(
            &ctx.connection_id,
            &ctx.filter_name,
            key,
            value.as_bytes().to_vec(),
        );
        accumulate(op_stats);

        matches!(
            outcome,
            crate::mitm::flow::state_store::StatePutOutcome::Stored
                | crate::mitm::flow::state_store::StatePutOutcome::Replaced
        )
    })
        .unwrap_or(false)
}

pub fn state_delete(key: &str) -> bool {
    with_context(|ctx| {
        let Some(store) = ctx.store.as_ref() else {
            return false;
        };

        let op_stats = store.delete(&ctx.connection_id, &ctx.filter_name, key);
        let deleted = op_stats.evicted_items > 0;
        accumulate(op_stats);
        deleted
    })
        .unwrap_or(false)
}