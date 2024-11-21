-- name: GetFeeds :many
SELECT
    *
FROM
    rss_feeds;

-- name: GetFeedsUpdatable :many
SELECT
    *
FROM
    rss_feeds
WHERE
    updated_at < NOW() - 300;

-- name: MarkUpdated :exec
UPDATE rss_feeds
SET
    updated_at = NOW()
WHERE
    id = ?;

-- name: GetViewFeeds :many
SELECT
    rss_feeds.*
FROM
    rss_feeds
    LEFT JOIN view_items ON rss_feeds.id = view_items.feed_id
WHERE
    view_items.view_id = ?;

-- name: GetViewFeedsItems :many
SELECT
    rss_feed_items.*
FROM
    rss_feed_items
    LEFT JOIN view_items ON rss_feed_items.rss_feed_id = view_items.feed_id
WHERE
    view_items.view_id = ?
ORDER BY
    rss_feed_items.published_at DESC
LIMIT
    ?;

-- name: CreateUser :execresult
INSERT INTO
    users (email, password)
VALUES
    (?, ?);

-- name: GetUserByEmail :one
SELECT
    *
FROM
    users
WHERE
    email = ?
LIMIT
    1;

-- name: CreateFeed :execresult
INSERT INTO
    rss_feeds (title, url, reference_count)
VALUES
    (?, ?, 1) ON DUPLICATE KEY
UPDATE reference_count = reference_count + 1;

-- name: GetFeedByURL :one
SELECT
    *
FROM
    rss_feeds
WHERE
    url = ?
LIMIT
    1;

-- name: DeleteFeed :exec
DELETE FROM rss_feeds
WHERE
    id = ?;

-- name: CreateView :execresult
INSERT INTO
    views (name, public, slug)
VALUES
    (?, ?, ?);

-- name: AddFeedToView :exec
INSERT INTO
    view_items (view_id, feed_id)
VALUES
    (?, ?);

-- name: GetViewBySlug :one
SELECT
    *
FROM
    views
WHERE
    slug = ?
LIMIT
    1;

-- name: GetUserViews :many
SELECT
    views.*
FROM
    views
    JOIN user_views ON views.id = user_views.view_id
WHERE
    user_views.user_id = ?;

-- name: CreateUserView :exec
INSERT INTO
    user_views (user_id, view_id)
VALUES
    (?, ?);

-- name: CreateFeedItem :exec
INSERT IGNORE INTO rss_feed_items (rss_feed_id, title, url, published_at)
VALUES
    (?, ?, ?, ?);

-- name: GetLatestFeedItems :many
SELECT
    *
FROM
    rss_feed_items
WHERE
    rss_feed_id = ?
ORDER BY
    published_at DESC
LIMIT
    30;

-- name: CreateSession :execresult
INSERT INTO
    sessions (user_id, token, expires_at)
VALUES
    (?, ?, ?);

-- name: GetSessionByToken :one
SELECT
    *
FROM
    sessions
WHERE
    token = ?
    AND expires_at > NOW()
LIMIT
    1;

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE
    id = ?;

-- name: GCSessions :exec
DELETE FROM sessions
WHERE
    expires_at < NOW();

-- name: DeleteView :exec
DELETE v,
vi,
uv
FROM
    views v
    LEFT JOIN view_items vi ON v.id = vi.view_id
    LEFT JOIN user_views uv ON v.id = uv.view_id
WHERE
    v.id = ?;

-- name: DecrementFeedRefCount :exec
UPDATE rss_feeds
SET
    reference_count = reference_count - 1
WHERE
    id = ?;

-- name: GetFeedRefCount :one
SELECT
    reference_count
FROM
    rss_feeds
WHERE
    id = ?;

-- name: RemoveFeedFromView :exec
DELETE FROM view_items
WHERE
    view_id = ?
    AND feed_id = ?;

-- name: GetAllViews :many
SELECT
    *
FROM
    views
ORDER BY
    created_at DESC;