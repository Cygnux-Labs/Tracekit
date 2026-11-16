# Signer API reference

The signer answers one request at a time, each a JSON object that names its RPC in the `method` field. This page lists
what each RPC takes and returns. The field tables are written from `tracekit/signer/rpc_schema.py` by
`scripts/api_doc.py`: edit the schema, run the script, never the tables.

## `approval_abandon`

TODO: what this RPC is for.

<!-- api-doc:begin approval_abandon -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `request_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `run_token` | text | yes | 1 to 1024 characters |
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `reason` | text | no | up to 1024 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `approval_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `state` | one of `requested`, `approved`, `rejected`, `expired`, `consumed` | yes |  |

</details>
<!-- api-doc:end approval_abandon -->

## `content_get`

Reads the content of records in a run: for each `seq` asked for, the content and its salt, the content marked redacted,
or the reason there is none.

<!-- api-doc:begin content_get -->
<details>
<summary>Request and answer fields</summary>

**Request**

| Field | Type | Required | Notes |
|---|---|---|---|
| `run_id` | text | yes | 1 to 128 characters; matches `^[A-Za-z0-9._:-]+(?![\s\S])` |
| `seqs` | list of whole numbers | yes | up to 1000 items |
| `purpose` | text | yes | 1 to 512 characters |

**Answer**

| Field | Type | Required | Notes |
|---|---|---|---|
| `items` | list of objects | yes | up to 1000 items |
| `items[].seq` | whole number | yes |  |
| `items[].content` | any value | no |  |
| `items[].salt` | text | no | up to 64 characters |
| `items[].redacted` | always `true` | no |  |
| `items[].type` | text | no | up to 64 characters |
| `items[].source` | text | no | up to 256 characters |
| `items[].state` | one of `not_retained`, `too_large`, `erased` | no |  |

</details>
<!-- api-doc:end content_get -->
