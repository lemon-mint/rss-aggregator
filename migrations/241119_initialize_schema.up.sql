CREATE TABLE
    rss_feeds (
        id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,
        title TEXT NOT NULL,
        url TEXT NOT NULL,
        reference_count BIGINT NOT NULL DEFAULT 0,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE
    rss_feed_items (
        id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,
        rss_feed_id BIGINT NOT NULL,
        title TEXT NOT NULL,
        url TEXT NOT NULL,
        published_at TIMESTAMP NOT NULL,
        added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE INDEX idx_rss_feed_items_rss_feed_id ON rss_feed_items (rss_feed_id);
CREATE INDEX idx_rss_feed_items_rss_feed_id_added_at ON rss_feed_items (rss_feed_id, added_at);
CREATE UNIQUE INDEX idx_rss_feed_items_rss_feed_id_url ON rss_feed_items (rss_feed_id, url);

CREATE TABLE
    users (
        id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE TABLE
    views (
        id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,
        name TEXT NOT NULL,
        public BOOLEAN NOT NULL,
        slug TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE INDEX views_slug_idx ON views (slug);

CREATE TABLE
    view_items (
        id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,
        view_id BIGINT NOT NULL,
        feed_id BIGINT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE INDEX view_items_view_id_idx ON view_items (view_id);
CREATE UNIQUE INDEX view_items_view_id_feed_id_idx ON view_items (view_id, feed_id);

CREATE TABLE
    user_views (
        user_id BIGINT NOT NULL,
        view_id BIGINT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, view_id)
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

CREATE INDEX user_views_user_id_idx ON user_views (user_id);
