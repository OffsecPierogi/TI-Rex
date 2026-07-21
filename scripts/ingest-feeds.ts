import "dotenv/config";
import { prisma } from "../src/lib/db";

const FEEDS = [
  { source: "CrowdStrike", url: "https://www.crowdstrike.com/en-us/blog/feed/" },
  { source: "GuidePoint Security", url: "https://www.guidepointsecurity.com/blog/feed/" },
  { source: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/" },
  { source: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews" },
  { source: "Cisco Talos", url: "https://blog.talosintelligence.com/rss/" },
  { source: "Unit 42", url: "https://unit42.paloaltonetworks.com/feed/" },
  { source: "SentinelOne Labs", url: "https://www.sentinelone.com/labs/feed/" },
  { source: "Microsoft Security", url: "https://www.microsoft.com/en-us/security/blog/feed/" },
  { source: "Recorded Future", url: "https://www.recordedfuture.com/feed" },
  { source: "Proofpoint", url: "https://www.proofpoint.com/us/rss.xml" },
  { source: "Krebs on Security", url: "https://krebsonsecurity.com/feed/" },
  { source: "Red Canary", url: "https://redcanary.com/blog/feed/" },
  { source: "Volexity", url: "https://www.volexity.com/feed/" },
  { source: "Elastic Security Labs", url: "https://www.elastic.co/security-labs/rss/feed.xml" },
  { source: "WeLiveSecurity (ESET)", url: "https://www.welivesecurity.com/en/feed/" },
  { source: "Huntress", url: "https://www.huntress.com/blog/rss.xml" },
  { source: "Google Threat Intelligence", url: "https://cloud.google.com/blog/topics/threat-intelligence/rss/" },
];

function stripHtml(html: string): string {
  return html.replace(new RegExp("<![CDATA[(.*?)]]>", "gs"), "$1").replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#039;/g, "'").replace(/&nbsp;/g, " ").replace(/\s+/g, " ").trim();
}

function extractTag(xml: string, tag: string): string {
  const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "i");
  const m = xml.match(re);
  return m ? m[1].trim() : "";
}

function extractAttr(xml: string, tag: string, attr: string): string {
  const re = new RegExp(`<${tag}[^>]*${attr}="([^"]*)"`, "i");
  const m = xml.match(re);
  return m ? m[1] : "";
}

interface ParsedItem {
  title: string;
  url: string;
  author: string | null;
  summary: string | null;
  publishedAt: Date | null;
  tags: string[];
}

function parseRssItems(xml: string): ParsedItem[] {
  const items: ParsedItem[] = [];

  const isAtom = xml.includes("<feed") && xml.includes("xmlns=\"http://www.w3.org/2005/Atom\"");

  if (isAtom) {
    const entries = xml.split(/<entry[\s>]/).slice(1);
    for (const entry of entries) {
      const title = stripHtml(extractTag(entry, "title"));
      const url = extractAttr(entry, "link", "href") || extractTag(entry, "link");
      if (!title || !url) continue;
      const summary = stripHtml(extractTag(entry, "summary") || extractTag(entry, "content")).slice(0, 500);
      const author = stripHtml(extractTag(extractTag(entry, "author"), "name")) || null;
      const published = extractTag(entry, "published") || extractTag(entry, "updated");
      const tags: string[] = [];
      const catMatches = entry.matchAll(/<category[^>]*term="([^"]+)"/g);
      for (const m of catMatches) tags.push(m[1]);
      items.push({
        title,
        url: url.startsWith("http") ? url : `https:${url}`,
        author,
        summary: summary || null,
        publishedAt: published ? new Date(published) : null,
        tags,
      });
    }
  } else {
    const rssItems = xml.split(/<item[\s>]/).slice(1);
    for (const item of rssItems) {
      const title = stripHtml(extractTag(item, "title"));
      const url = stripHtml(extractTag(item, "link"));
      if (!title || !url) continue;
      const desc = stripHtml(extractTag(item, "description") || extractTag(item, "content:encoded")).slice(0, 500);
      const author = stripHtml(extractTag(item, "dc:creator") || extractTag(item, "author")) || null;
      const pubDate = extractTag(item, "pubDate") || extractTag(item, "dc:date");
      const tags: string[] = [];
      const catMatches = item.matchAll(/<category[^>]*>([^<]+)<\/category>/g);
      for (const m of catMatches) tags.push(stripHtml(m[1]));
      items.push({
        title,
        url,
        author,
        summary: desc || null,
        publishedAt: pubDate ? new Date(pubDate) : null,
        tags,
      });
    }
  }

  return items;
}

async function fetchFeed(source: string, url: string): Promise<number> {
  console.log(`  Fetching ${source}...`);
  const resp = await fetch(url, {
    headers: { "User-Agent": "ThreatIntelDashboard/1.0" },
    redirect: "follow",
    signal: AbortSignal.timeout(30000),
  });
  if (!resp.ok) {
    console.log(`    HTTP ${resp.status} — skipping`);
    return 0;
  }
  const xml = await resp.text();
  const items = parseRssItems(xml);
  console.log(`    Parsed ${items.length} items`);

  let created = 0;
  for (const item of items) {
    try {
      await prisma.feedItem.upsert({
        where: { url: item.url },
        create: {
          title: item.title,
          url: item.url,
          source,
          author: item.author,
          summary: item.summary,
          publishedAt: item.publishedAt,
          tags: item.tags.length > 0 ? JSON.stringify(item.tags) : null,
        },
        update: {
          title: item.title,
          author: item.author,
          summary: item.summary,
          publishedAt: item.publishedAt,
          tags: item.tags.length > 0 ? JSON.stringify(item.tags) : null,
        },
      });
      created++;
    } catch {
      // duplicate URL — skip
    }
  }
  console.log(`    Upserted ${created} items`);
  return created;
}

async function main() {
  console.log("Ingesting threat feeds...\n");
  let total = 0;
  for (const feed of FEEDS) {
    try {
      total += await fetchFeed(feed.source, feed.url);
    } catch (err) {
      console.log(`    Error: ${err instanceof Error ? err.message : err}`);
    }
  }
  console.log(`\nDone. ${total} total items upserted.`);
}

main().catch(console.error).finally(() => prisma.$disconnect());
