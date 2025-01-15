# Tests

## Client

Before running policy tests for a client, set up a database with indexed data from
coston2 blockchain. Navigate to `tests/docker` and run

```bash
docker compose up
```

This will start an indexer and a database. Wait a bit for the indexer to put some data in the database.

Now you can run test

```bash
go test -v tee-node/client/policy
```
