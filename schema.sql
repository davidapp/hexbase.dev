-- hexbase.dev D1 schema + seed data.
-- Apply locally:  npm run db:local
-- Apply remotely: npm run db:remote
-- Re-running re-seeds the links directory; shares are preserved.

CREATE TABLE IF NOT EXISTS shares (
  code TEXT PRIMARY KEY,
  tool TEXT NOT NULL,
  filename TEXT,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shares_expires ON shares (expires_at);

DROP TABLE IF EXISTS links;
CREATE TABLE links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT NOT NULL,
  category_sort INTEGER NOT NULL,
  title TEXT NOT NULL,
  url TEXT NOT NULL,
  description TEXT NOT NULL,
  sort INTEGER NOT NULL DEFAULT 0
);

INSERT INTO links (category, category_sort, title, url, description, sort) VALUES
-- Docs & references
('Docs & References', 1, 'MDN Web Docs', 'https://developer.mozilla.org', 'The web platform, documented. HTML, CSS, JS, Web APIs — start here.', 1),
('Docs & References', 1, 'DevDocs', 'https://devdocs.io', '100+ API docs in one fast, offline-capable, fuzzy-searchable UI.', 2),
('Docs & References', 1, 'Can I use', 'https://caniuse.com', 'Browser support tables for every web platform feature.', 3),
('Docs & References', 1, 'web.dev', 'https://web.dev', 'Guidance on performance, PWAs and modern web capabilities.', 4),
('Docs & References', 1, 'HTTP Working Group specs', 'https://httpwg.org/specs/', 'The HTTP standards (RFC 9110–9114) in readable HTML.', 5),
('Docs & References', 1, 'OpenAPI Specification', 'https://spec.openapis.org/oas/latest.html', 'The standard for describing REST APIs.', 6),

-- Standards & RFCs
('Standards & RFCs', 2, 'IETF Datatracker', 'https://datatracker.ietf.org', 'Every RFC and internet-draft, with status and history.', 1),
('Standards & RFCs', 2, 'RFC Editor', 'https://www.rfc-editor.org', 'The canonical archive of RFCs since 1969.', 2),
('Standards & RFCs', 2, 'IANA Protocol Registries', 'https://www.iana.org/protocols', 'Port numbers, media types, header names — the internet''s constants.', 3),
('Standards & RFCs', 2, 'WHATWG HTML', 'https://html.spec.whatwg.org/multipage/', 'The living HTML standard, as browsers actually implement it.', 4),
('Standards & RFCs', 2, 'TC39 / ECMAScript', 'https://tc39.es', 'JavaScript language proposals and the ECMAScript spec.', 5),
('Standards & RFCs', 2, 'W3C Technical Reports', 'https://www.w3.org/TR/', 'CSS, accessibility, XML and the rest of the W3C stack.', 6),
('Standards & RFCs', 2, 'Unicode Character Charts', 'https://www.unicode.org/charts/', 'Every character, every block, every code point.', 7),

-- Playgrounds
('Playgrounds', 3, 'Compiler Explorer', 'https://godbolt.org', 'See what your C/C++/Rust/Go compiles to, instruction by instruction.', 1),
('Playgrounds', 3, 'regex101', 'https://regex101.com', 'Build and debug regular expressions with live explanation.', 2),
('Playgrounds', 3, 'TypeScript Playground', 'https://www.typescriptlang.org/play', 'Try TS features and inspect the emitted JS and types.', 3),
('Playgrounds', 3, 'Go Playground', 'https://go.dev/play/', 'Run and share Go snippets.', 4),
('Playgrounds', 3, 'Rust Playground', 'https://play.rust-lang.org', 'Run Rust with any edition, channel and crate set.', 5),
('Playgrounds', 3, 'SQLite Fiddle', 'https://sqlite.org/fiddle/', 'Full SQLite in your browser via WASM, by the SQLite team.', 6),
('Playgrounds', 3, 'jqplay', 'https://jqplay.org', 'Test jq filters against your JSON.', 7),
('Playgrounds', 3, 'crontab.guru', 'https://crontab.guru', 'Decode and compose cron expressions.', 8),
('Playgrounds', 3, 'explainshell', 'https://explainshell.com', 'Paste a shell one-liner, get each flag explained from the man pages.', 9),

-- Networking
('Networking', 4, 'Cloudflare Radar', 'https://radar.cloudflare.com', 'Live internet traffic, outages, attacks and protocol adoption.', 1),
('Networking', 4, 'Hurricane Electric BGP Toolkit', 'https://bgp.he.net', 'Look up any ASN, prefix or IP and its routing state.', 2),
('Networking', 4, 'RIPEstat', 'https://stat.ripe.net', 'Deep data on IP space: routing, DNS, geolocation, history.', 3),
('Networking', 4, 'DNSViz', 'https://dnsviz.net', 'Visualize a domain''s DNSSEC chain and spot breakage.', 4),
('Networking', 4, 'MXToolbox', 'https://mxtoolbox.com', 'MX, SPF, DKIM, blacklist and SMTP diagnostics.', 5),
('Networking', 4, 'Wireshark OUI Lookup', 'https://www.wireshark.org/tools/oui-lookup.html', 'Which vendor owns a MAC address prefix.', 6),
('Networking', 4, 'test-ipv6', 'https://test-ipv6.com', 'Is your connection IPv6-ready, and if not, why.', 7),

-- Security
('Security', 5, 'OWASP', 'https://owasp.org', 'The Top 10, cheat sheets and testing guides for appsec.', 1),
('Security', 5, 'CVE.org', 'https://www.cve.org', 'The canonical vulnerability identifier database.', 2),
('Security', 5, 'NVD', 'https://nvd.nist.gov', 'CVEs with CVSS scores and affected-product data.', 3),
('Security', 5, 'crt.sh', 'https://crt.sh', 'Search Certificate Transparency logs — find every cert for a domain.', 4),
('Security', 5, 'Have I Been Pwned', 'https://haveibeenpwned.com', 'Check whether an email or password appears in known breaches.', 5),
('Security', 5, 'SSL Labs Server Test', 'https://www.ssllabs.com/ssltest/', 'Grade a server''s TLS configuration.', 6),
('Security', 5, 'Security Headers', 'https://securityheaders.com', 'Scan a site''s HTTP response headers.', 7),

-- Package registries
('Package Registries', 6, 'npm', 'https://www.npmjs.com', 'JavaScript packages.', 1),
('Package Registries', 6, 'PyPI', 'https://pypi.org', 'Python packages.', 2),
('Package Registries', 6, 'crates.io', 'https://crates.io', 'Rust crates.', 3),
('Package Registries', 6, 'Maven Central', 'https://central.sonatype.com', 'Java/JVM artifacts.', 4),
('Package Registries', 6, 'pkg.go.dev', 'https://pkg.go.dev', 'Go modules and their docs.', 5),
('Package Registries', 6, 'NuGet', 'https://www.nuget.org', '.NET packages.', 6),
('Package Registries', 6, 'Packagist', 'https://packagist.org', 'PHP / Composer packages.', 7),
('Package Registries', 6, 'RubyGems', 'https://rubygems.org', 'Ruby gems.', 8),

-- Learning
('Learning', 7, 'roadmap.sh', 'https://roadmap.sh', 'Skill-tree style paths for every developer role.', 1),
('Learning', 7, 'Exercism', 'https://exercism.org', 'Practice 70+ languages with mentor feedback. Free.', 2),
('Learning', 7, 'The Missing Semester', 'https://missing.csail.mit.edu', 'MIT''s course on the tools nobody teaches: shell, git, debugging.', 3),
('Learning', 7, 'Beej''s Guide to Network Programming', 'https://beej.us/guide/bgnet/', 'The classic, friendly intro to sockets — pairs well with our packet decoder.', 4),
('Learning', 7, 'Crafting Interpreters', 'https://craftinginterpreters.com', 'Build two interpreters from scratch. Free book, beautifully written.', 5),
('Learning', 7, 'Nand2Tetris', 'https://www.nand2tetris.org', 'Build a computer from NAND gates up to Tetris.', 6),
('Learning', 7, 'CS50x', 'https://cs50.harvard.edu/x/', 'Harvard''s legendary intro to computer science.', 7),

-- News & communities
('News & Communities', 8, 'Hacker News', 'https://news.ycombinator.com', 'The industry watercooler.', 1),
('News & Communities', 8, 'Lobsters', 'https://lobste.rs', 'Smaller, tag-driven, invite-only HN alternative.', 2),
('News & Communities', 8, 'Stack Overflow', 'https://stackoverflow.com', 'Still where the answers are.', 3),
('News & Communities', 8, 'GitHub Trending', 'https://github.com/trending', 'What the ecosystem is starring this week.', 4),
('News & Communities', 8, 'DEV Community', 'https://dev.to', 'Blogging platform for developers.', 5),
('News & Communities', 8, 'arXiv CS', 'https://arxiv.org/list/cs/recent', 'Preprints — where ML and systems research lands first.', 6);
