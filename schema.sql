CREATE TABLE IF NOT EXISTS runs (
 id bigserial PRIMARY KEY, snapshot_hash text UNIQUE NOT NULL,
 snapshot jsonb NOT NULL, active boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(), total bigint NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_run ON runs ((active)) WHERE active;
CREATE TABLE IF NOT EXISTS routes (
 run_id bigint REFERENCES runs ON DELETE CASCADE, asn bigint NOT NULL,
 name text, prefix cidr NOT NULL, details jsonb NOT NULL,
 PRIMARY KEY(run_id, asn, prefix)
);
CREATE TABLE IF NOT EXISTS lookup_ranges (
 run_id bigint REFERENCES runs ON DELETE CASCADE, prefix cidr NOT NULL,
 PRIMARY KEY(run_id,prefix)
);
CREATE TABLE IF NOT EXISTS workers (
 instance uuid PRIMARY KEY, hostname text NOT NULL, run_id bigint REFERENCES runs,
 started_at timestamptz NOT NULL DEFAULT now(), heartbeat timestamptz NOT NULL DEFAULT now(),
 state text NOT NULL DEFAULT 'running', requests bigint NOT NULL DEFAULT 0,
 saved bigint NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS jobs (
 id bigserial PRIMARY KEY, run_id bigint REFERENCES runs ON DELETE CASCADE,
 first_ip inet NOT NULL, last_ip inet NOT NULL,
 size integer NOT NULL CHECK(size BETWEEN 1 AND 256),
 done boolean NOT NULL DEFAULT false, ready_at timestamptz NOT NULL DEFAULT now(),
 owner uuid REFERENCES workers(instance), token uuid, lease_until timestamptz,
 UNIQUE(run_id,first_ip,last_ip)
);
CREATE INDEX IF NOT EXISTS job_queue ON jobs(run_id,ready_at,id) WHERE NOT done;
CREATE TABLE IF NOT EXISTS observations (
 run_id bigint REFERENCES runs ON DELETE CASCADE, ip inet NOT NULL,
 status text NOT NULL CHECK(status IN ('ok','no_data','retry','exhausted')),
 attempts integer NOT NULL DEFAULT 0, next_retry timestamptz NOT NULL DEFAULT now(),
 payload jsonb, error text, fetched_at timestamptz NOT NULL DEFAULT now(),
 worker uuid REFERENCES workers(instance), PRIMARY KEY(run_id,ip)
);
CREATE TABLE IF NOT EXISTS run_counts (
 run_id bigint REFERENCES runs ON DELETE CASCADE,
 status text NOT NULL, count bigint NOT NULL DEFAULT 0, PRIMARY KEY(run_id,status)
);
CREATE OR REPLACE FUNCTION count_observations() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP = 'UPDATE' AND OLD.status = NEW.status THEN RETURN NEW; END IF;
 IF TG_OP = 'UPDATE' THEN
  UPDATE run_counts SET count=count-1 WHERE run_id=OLD.run_id AND status=OLD.status;
 END IF;
 INSERT INTO run_counts VALUES(NEW.run_id,NEW.status,1)
 ON CONFLICT(run_id,status) DO UPDATE SET count=run_counts.count+1;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS observation_counts ON observations;
CREATE TRIGGER observation_counts AFTER INSERT OR UPDATE ON observations
 FOR EACH ROW EXECUTE FUNCTION count_observations();
CREATE TABLE IF NOT EXISTS pacing (
 id integer PRIMARY KEY CHECK(id=1), rate double precision NOT NULL CHECK(rate>0),
 next_at timestamptz NOT NULL DEFAULT now(), cooldown_until timestamptz NOT NULL DEFAULT now()
);
INSERT INTO pacing(id,rate) VALUES(1,2) ON CONFLICT DO NOTHING;
