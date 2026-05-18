# Scheduler integration

The strategy scheduler combines:

- Strategy Graph
- Transition Cost Matrix
- Bayesian Priors
- Adaptive Scoring
- TSP-like Local Ordering
- Early Pruning
- Parallel Workers

Concurrency is bounded by `min(workers.count, queue.qnum_count)`.

Early pruning can cancel queued tasks and optionally active tasks through `CancellationToken`. Results update scoring only if the failure is not classified as `InfrastructureFailure`.
