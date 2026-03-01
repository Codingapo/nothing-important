import express from "express";
import fetch from "node-fetch";
import path from "path";
import { fileURLToPath } from "url";
import axios from "axios";
import Srt2Vtt from "srt-to-vtt";
import cors from "cors";
import session from "express-session"; // ✅ Added for session management
import http from "http";
// ==================== PREMIUM SUBSCRIPTION SYSTEM ====================
import mysql from "mysql2/promise";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const allowedOrigins = [
  'https://moviewatchtv.fun',
  'https://www.moviewatchtv.fun',
  'https://moviewatch.xo.je',
];
app.use(cors());
const PORT = 4000;
// Session middleware to store user-specific cookies
app.use(
  session({
    secret: "SKALAHANTE", // Replace with a secure key
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days, matching account cookie
      httpOnly: true,
      secure: false, // Set to true if using HTTPS
      sameSite: "none"
    }
  })
);
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// MySQL Pool - CHANGE TO YOUR SHARED DB CREDENTIALS
const pool = mysql.createPool({
  host: "localhost", // e.g., localhost or 127.0.0.1 or cloud IP
  user: "phpmyadmin",
  password: "Cracker$5562",
  database: "moviewatch",
  waitForConnections: true,
  connectionLimit: 10,
});
// API: Register Firebase user in MySQL (called silently on signup)
app.post("/api/register-user", async (req, res) => {
  const { firebase_uid, email } = req.body;
  if (!firebase_uid || !email) {
    return res.status(400).json({ error: "Missing data" });
  }
  try {
    await pool.execute(
      `INSERT INTO users (firebase_uid, email, is_subscribed, days_left, created_at)
       VALUES (?, ?, 0, 0, NOW())
       ON DUPLICATE KEY UPDATE email = ?`,
      [firebase_uid, email, email]
    );
    console.log(`User registered: ${email}`);
    res.json({ success: true });
  } catch (err) {
    console.error("DB Error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.get("/version.json", (req, res) => {
  res.json({
    latest_version: "1.3",
    update_url: "https://moviewatchtv.fun/download",
    force_update: true
  });
});
// API: Check subscription status
app.get("/api/check-subscription", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ subscribed: false });
  try {
    const [rows] = await pool.execute(
      "SELECT is_subscribed, days_left FROM users WHERE email = ?",
      [email]
    );
    if (rows.length === 0) {
      return res.json({ subscribed: false, days_left: 0 });
    }
    const user = rows[0];
    const subscribed = user.is_subscribed === 1 && user.days_left > 0;
    res.json({
      subscribed,
      days_left: Number(user.days_left),
      message: subscribed ? "Premium Active" : "Free User"
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ subscribed: false });
  }
});
// Function to get a working MovieBox domain (with fallback)
async function getMovieboxDomain(req, res) {
  // Return cached domain if available
  if (req.session.movieboxDomain) {
    return req.session.movieboxDomain;
  }
  const domains = ['moviebox.ph', 'movie-box.tv', 'moviebox.ac', 'moviebox.biz' , 'moviebox.pk' ,'movieboxapp.in' , 'moviebox.id'];
  for (const domain of domains) {
    try {
      const response = await fetch(`https://${domain}/wefeed-h5-bff/web/home`, {
        headers: {
          Accept: "application/json",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"
        },
        // Optional: set timeout to avoid hanging
      });
      if (response.ok && response.headers.get('content-type')?.includes('application/json')) {
        req.session.movieboxDomain = domain; // cache working domain
        console.log(`Selected working domain: ${domain}`);
        return domain;
      }
    } catch (error) {
      console.warn(`Domain ${domain} failed: ${error.message}`);
    }
  }
  // If none work, throw error or return null instead of picking a random one
  console.error('No working Moviebox domain found.');
  return null; // or throw new Error('No working Moviebox domain');
}
// Base URLs (now dynamic via getMovieboxDomain)
// const BASE_URL = "https://moviebox.ph/wefeed-h5-bff/web/subject/search"; // Removed, now dynamic
const COOKIE_URL = "https://fmoviesunblocked.net/wefeed-h5-bff/web/subject/play";
// Function to fetch a new account cookie for a user
async function fetchUserCookie(timezone, subjectId = "6882010391132918816", detailPath = "god-friended-me-qRSZ2fcGnc8") {
  try {
    const response = await axios.get(COOKIE_URL, {
      params: { subjectId, se: 0, ep: 0, detail_path: detailPath },
      headers: {
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.5",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
        "X-Client-Info": JSON.stringify({ timezone }),
        "Referer": `https://fmoviesunblocked.net/spa/videoPlayPage/movies/${detailPath}?id=${subjectId}&type=/movie/detail&lang=en`
      }
    });
    const cookies = response.headers["set-cookie"];
    if (cookies) {
      const accountCookie = cookies.find(cookie => cookie.includes("account="));
      if (accountCookie) {
        const cookieParts = accountCookie.split(";")[0].split("=");
        return {
          name: cookieParts[0],
          value: cookieParts[1],
          attributes: accountCookie.split(";").slice(1).map(attr => attr.trim())
        };
      }
    }
    return null;
  } catch (error) {
    console.error("Error fetching cookie:", error.message);
    return null;
  }
}
// Middleware to ensure user has a cookie
async function ensureUserCookie(req, res, next) {
  if (!req.session.accountCookie) {
    // Derive timezone from X-Client-Info header or default to request header
    const clientInfo = req.headers["x-client-info"] ? JSON.parse(req.headers["x-client-info"]) : { timezone: "Africa/Johannesburg" };
    const timezone = clientInfo.timezone || "Africa/Johannesburg";
    // Fetch a new cookie for the user
    const cookie = await fetchUserCookie(timezone);
    if (cookie) {
      req.session.accountCookie = cookie;
      console.log(`Assigned new cookie for session ${req.session.id}: ${cookie.name}=${cookie.value}`);
    } else {
      console.warn("Failed to fetch cookie for session", req.session.id);
    }
  }
  next();
}
app.get("/proxy", async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "URL is required" });
  try {
    const response = await axios.get(url);
    res.setHeader("Content-Type", "application/json");
    res.send(response.data);
  } catch (err) {
    console.error("Proxy error:", err.message);
    res.status(500).json({ error: "Failed to fetch remote URL" });
  }
});
// Search endpoint (now with dynamic domain)
async function searchVideo(domain, keyword, page = 1, perPage = 24, subjectType = 0) {
  const baseUrl = `https://${domain}/wefeed-h5-bff/web/subject/search`;
  try {
    const response = await axios.post(
      baseUrl,
      { keyword, page, perPage, subjectType },
      {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
          "Accept": "application/json",
          "Content-Type": "application/json",
          "Referer": `https://${domain}/web/searchResult?keyword=${encodeURIComponent(keyword)}`,
          "Origin": `https://${domain}`,
          "X-Client-Info": JSON.stringify({ timezone: "Africa/Johannesburg" })
        }
      }
    );
    return response.data;
  } catch (error) {
    console.error("Error searching video:", error.response?.data || error.message);
    throw error;
  }
}
app.post("/search", async (req, res) => {
  try {
    const domain = await getMovieboxDomain(req, res);
    const { keyword, page = 1, perPage = 24, subjectType = 0 } = req.body;
    if (!keyword) {
      return res.status(400).json({ error: "Keyword is required" });
    }
    const data = await searchVideo(domain, keyword, page, perPage, subjectType);
    res.json(data);
  } catch (err) {
    console.error("Search endpoint error:", err.message);
    res.status(500).json({ error: "Failed to search videos" });
  }
});
// Proxy home endpoint (now with dynamic domain)
app.get("/crack/home", async (req, res) => {
  try {
    const domain = await getMovieboxDomain(req, res);
    const remoteUrl = `https://${domain}/wefeed-h5-bff/web/home`;
    const response = await fetch(remoteUrl, {
      headers: {
        Accept: "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"
      }
    });
    if (!response.ok) {
      return res.status(response.status).json({ error: `Upstream error: ${response.statusText}` });
    }
    const json = await response.json();
    res.json(json);
  } catch (err) {
    console.error("Error fetching remote JSON:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});
const SOURCE_URL = "http://localhost:4000/crack/home";
// Or: "https://moviewatchtv.fun/crack/home"
app.get("/api/clean", async (req, res) => {
  try {
    const response = await fetch(SOURCE_URL);
    const data = await response.json();
    const operating = data?.data?.operatingList || [];
    // Helper: extract only needed fields from a movie/subject
    const minimize = (item) => ({
      subjectId: item.subjectId || item.id,
      subjectType: item.subjectType,
      title: item.title,
      detailPath: item.detailPath,
      cover: { url: item.cover?.url },
      imdbRatingValue: item.imdbRatingValue || null
    });
    // Helper: get all sections matching keywords (case-insensitive)
    const getSections = (keywords) =>
      operating.filter(op =>
        typeof op.title === "string" &&
        keywords.some(kw => op.title.toLowerCase().includes(kw))
      );
    // Define your categories and keywords
    const categories = {
      tuDrama: ["turkish drama"],
      saDrama: ["sa drama"],
      western: ["western"],
      anime:["anime"],
      popular: ["popular"],
          hot: ["hot short tv"],
       horror: ["horror"],
      action: ["action movies"],
      trending: ["trending"],
      adventure: ["adventure"],
      tRomance: ["teen romance"],
      nollywood: ["nollywood"],
      kDrama: ["k-drama"],
      cDrama: ["c-drama"],
      tDrama: ["thai-drama"]
    };
    // Build sections dynamically
    const sections = {};
    for (const [key, keywords] of Object.entries(categories)) {
      const matchedSections = getSections(keywords);
      const items = matchedSections.flatMap(sec => (sec.subjects || []).map(minimize));
      if (items.length > 0) {
        sections[key] = items;
      }
    }
    // Get banner and filter sections
    const bannerSection = operating.find(op => op.type === "BANNER");
    const filterSection = operating.find(op => op.type === "FILTER");
    const cleanJSON = {
      banner: bannerSection?.banner?.items || [],
      categories: filterSection?.filters || [],
      sections
    };
    res.json(cleanJSON);
  } catch (error) {
    console.error("CLEAN API ERROR:", error.message);
    res.status(500).json({ error: "Failed to process clean JSON" });
  }
});
app.get("/send-cookie", async (req, res) => {
  try {
    const cookie = await fetchUserCookie("Africa/Johannesburg"); // get valid cookie
    if (!cookie) {
      return res.status(500).json({ error: "Failed to fetch moviebox cookie" });
    }
    const payload = {
      cookie,
      sessionId: req.sessionID,
      timestamp: new Date().toISOString()
    };
    // Send the payload to the receiver via POST
    const postData = JSON.stringify(payload);
    const options = {
      hostname: '34.70.80.28',
      port: 4000,
      path: '/cookie',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    };
    const sendToReceiver = new Promise((resolve, reject) => {
      const reqToReceiver = http.request(options, (receiverRes) => { // Changed to http.request
        let data = '';
        receiverRes.on('data', chunk => { data += chunk; });
        receiverRes.on('end', () => {
          if (receiverRes.statusCode >= 200 && receiverRes.statusCode < 300) {
            resolve({ success: true, response: JSON.parse(data) });
          } else {
            reject(new Error(`Receiver responded with status ${receiverRes.statusCode}: ${data}`));
          }
        });
      });
      reqToReceiver.on('error', reject);
      reqToReceiver.write(postData);
      reqToReceiver.end();
    });
    // Wait for the send to complete, then respond to the original client
    await sendToReceiver;
    res.json({ success: true, message: "Cookie sent to receiver successfully" });
  } catch (err) {
    console.error("Error preparing or sending cookie:", err.message);
    res.status(500).json({ error: "Failed to prepare or send cookie" });
  }
});
// Recommendations endpoint (now with dynamic domain)
const fetchRecommendations = async (domain, subjectId, page = 1, perPage = 16) => {
  const url = `https://${domain}/wefeed-h5-bff/web/subject/detail-rec?subjectId=${subjectId}&page=${page}&perPage=${perPage}`;
  try {
    const res = await fetch(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"
      }
    });
    const json = await res.json();
    if (json.code !== 0) {
      throw new Error(`API error: ${json.message}`);
    }
    return json.data.items || [];
  } catch (err) {
    console.error("Error fetching recommendations:", err.message);
    return [];
  }
};
app.get("/detailRec/:subjectId", async (req, res) => {
  try {
    const domain = await getMovieboxDomain(req, res);
    const { subjectId } = req.params;
    const { page = 1 } = req.query;
    if (!subjectId) {
      return res.status(400).json({ error: "subjectId is required" });
    }
    const recommendations = await fetchRecommendations(domain, subjectId, page);
    if (recommendations.length === 0) {
      return res.status(404).json({ message: "No recommendations found." });
    }
    res.json({ subjectId, page: Number(page), results: recommendations });
  } catch (err) {
    console.error("Recommendations endpoint error:", err);
    res.status(500).json({ error: "Failed to fetch recommendations" });
  }
});
// Movie details endpoint (Updated with dynamic domain and spoofing headers)
app.get("/detail/:subjectId", async (req, res) => {
  try {
    const domain = await getMovieboxDomain(req, res);
    const { subjectId } = req.params;
    const url = `https://${domain}/wefeed-h5-bff/web/subject/detail?subjectId=${subjectId}`;
    const response = await fetch(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "Client-IP": "127.0.0.1"
      }
    });
    const json = await response.json();
    if (json.code !== 0) {
      return res.status(500).json({ error: `API error: ${json.message}` });
    }
    res.json(json.data);
  } catch (err) {
    console.error("Error fetching details:", err);
    res.status(500).json({ error: "Failed to fetch movie details" });
  }
});
// Proxy trending movies (now with dynamic domain)
app.get("/trending", async (req, res) => {
  try {
    const domain = await getMovieboxDomain(req, res);
    const url = `https://${domain}/wefeed-h5-bff/web/subject/trending?uid=5089247895077929680&page=1&perPage=18`;
    const response = await fetch(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"
      }
    });
    const json = await response.json();
    if (json.code !== 0) {
      return res.status(500).json({ error: `API error: ${json.message}` });
    }
    const movies = json.data.subjectList.map(movie => ({
      title: movie.title,
      releaseDate: movie.releaseDate,
      genre: movie.genre,
      subjectId: movie.subjectId,
      country: movie.countryName,
      rating: movie.imdbRatingValue,
      poster: movie.cover.url,
      link: `detail.html?path=${movie.detailPath}&id=${movie.subjectId}`
    }));
    res.json(movies);
  } catch (err) {
    console.error("Error fetching trending:", err);
    res.status(500).json({ error: "Failed to fetch trending movies" });
  }
});
// TV series endpoint (now with dynamic domain)
app.get("/get-tv-series", async (req, res) => {
  try {
    const domain = await getMovieboxDomain(req, res);
    const { page = 1, perPage = 24, channelId, genre, country, year, classify } = req.query;
    if (!channelId) {
      return res.status(400).json({ error: "channelId is required" });
    }
    const payload = {
      page: Number(page),
      perPage: Number(perPage),
      channelId: Number(channelId),
      genre: genre || "All",
      country: country || "All",
      year: year || "All",
      classify: classify || "All"
    };
    const response = await axios.post(
      `https://${domain}/wefeed-h5-bff/web/filter`,
      payload,
      {
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"
        }
      }
    );
    res.json(response.data);
  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: "Something went wrong" });
  }
});
// Get video info (size) endpoint
app.get("/getVideoInfo", async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: "URL required" });
  try {
    const response = await axios.head(url, {
      headers: {
        Referer: "https://fmoviesunblocked.net",
        Origin: "https://fmoviesunblocked.net"
      },
      timeout: 5000
    });
    const size = response.headers['content-length'];
    res.json({ size: size ? parseInt(size) : null });
  } catch (err) {
    console.error("Error getting video info:", err.message);
    res.status(500).json({ error: "Failed to get video size" });
  }
});
// Fetch video endpoint with user-specific cookie (Updated with spoofing headers)
app.get("/fetchVideo", ensureUserCookie, async (req, res) => {
  try {
    const { subjectId, detailPath, season = 1, episode = 1 } = req.query;
    if (!subjectId || !detailPath) {
      return res.status(400).json({ error: "Missing subjectId or detailPath" });
    }
    const cookie = req.session.accountCookie
      ? `${req.session.accountCookie.name}=${req.session.accountCookie.value}`
      : "";
    const response = await axios.get("https://fmoviesunblocked.net/wefeed-h5-bff/web/subject/play", {
      params: { subjectId, se: season, ep: episode, detail_path: detailPath },
      headers: {
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.5",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
        "X-Client-Info": JSON.stringify({ timezone: req.session.timezone || "Africa/Johannesburg" }),
        "Referer": `https://fmoviesunblocked.net/spa/videoPlayPage/movies/${detailPath}?id=${subjectId}&type=/movie/detail&lang=en`,
        "Cookie": cookie,
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "Client-IP": "127.0.0.1"
      }
    });
    // Update cookie if a new one is received
    const newCookies = response.headers["set-cookie"];
    if (newCookies && newCookies.find(c => c.includes("account="))) {
      const accountCookie = newCookies.find(c => c.includes("account="));
      const cookieParts = accountCookie.split(";")[0].split("=");
      req.session.accountCookie = {
        name: cookieParts[0],
        value: cookieParts[1],
        attributes: accountCookie.split(";").slice(1).map(attr => attr.trim())
      };
      console.log(`Updated cookie for session ${req.session.id}: ${cookieParts[0]}=${cookieParts[1]}`);
    }
    res.json(response.data.data.streams);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to fetch video" });
  }
});
// Fetch captions endpoint with user-specific cookie (Updated with spoofing headers)
app.get("/fetchCaptions", ensureUserCookie, async (req, res) => {
  try {
    const { subjectId, detailPath, season = 1, episode = 1 } = req.query;
    if (!subjectId || !detailPath) {
      return res.status(400).json({ error: "Missing subjectId or detailPath" });
    }
    const cookie = req.session.accountCookie
      ? `${req.session.accountCookie.name}=${req.session.accountCookie.value}`
      : "";
    const commonHeaders = {
      "Accept": "application/json",
      "Accept-Language": "en-US,en;q=0.5",
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
      "X-Client-Info": JSON.stringify({ timezone: req.session.timezone || "Africa/Johannesburg" }),
      "Referer": `https://fmoviesunblocked.net/spa/videoPlayPage/movies/${detailPath}?id=${subjectId}&type=/movie/detail&lang=en`,
      "Cookie": cookie,
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
      "Client-IP": "127.0.0.1"
    };
    const streamRes = await axios.get("https://fmoviesunblocked.net/wefeed-h5-bff/web/subject/play", {
      params: { subjectId, se: season, ep: episode, detail_path: detailPath },
      headers: commonHeaders
    });
    const streams = streamRes.data.data.streams;
    const streamId = streams[0].id;
    const captionsRes = await axios.get("https://fmoviesunblocked.net/wefeed-h5-bff/web/subject/caption", {
      params: { format: "MP4", id: streamId, subjectId, detail_path: detailPath },
      headers: commonHeaders
    });
    res.json(captionsRes.data.data.captions);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Failed to fetch captions" });
  }
});
// Proxy subtitle (.srt → .vtt) - Updated with explicit CORS headers for <track> compatibility
app.get("/subtitle", async (req, res) => {
  try {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: "URL is required" });
    // CORS headers
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type, Range");
    res.set("Access-Control-Expose-Headers", "Accept-Ranges, Content-Encoding, Content-Length, Content-Range");
    // Fetch the SRT subtitle and convert to VTT
    const response = await axios.get(url, { responseType: "stream" });
    res.setHeader("Content-Type", "text/vtt; charset=utf-8");
    response.data.pipe(Srt2Vtt()).pipe(res);
  } catch (err) {
    console.error("Subtitle fetch error:", err.message);
    res.status(500).send("Failed to fetch subtitle");
  }
});
// Handle preflight OPTIONS
app.options("/subtitle", (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type, Range");
  res.sendStatus(204);
});


// Optimized video proxy with Range support and proper filename
app.get("/streamVideo", async (req, res) => {
  try {
    const {
      url,
      download,
      type = "movie",
      title = "video",
      season,
      episode,
      year
    } = req.query;

    if (!url) return res.status(400).send("URL required");

    // -------- filename builder --------
    const safe = (str) =>
      String(str)
        .replace(/[\/\\?%*:|"<>]/g, "")
        .trim();

    let filename = "video.mp4";

    if (type === "tv" && season && episode) {
      const s = String(season).padStart(2, "0");
      const e = String(episode).padStart(2, "0");
      filename = `${safe(title)} - S${s}E${e}.mp4`;
    } else {
      filename = year
        ? `${safe(title)} (${year}).mp4`
        : `${safe(title)}.mp4`;
    }

    // -------- headers --------
    const range = req.headers.range;
    const headers = {
      Referer: "https://fmoviesunblocked.net",
      Origin: "https://fmoviesunblocked.net"
    };

    if (range) headers.Range = range;

    const response = await axios.get(url, {
      responseType: "stream",
      headers
    });

    // forward important headers
    Object.entries(response.headers).forEach(([key, value]) => {
      const k = key.toLowerCase();
      if (
        k === "content-length" ||
        k === "content-range" ||
        k === "accept-ranges" ||
        k === "content-type"
      ) {
        res.setHeader(key, value);
      }
    });

    // download support
    if (download === "1") {
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${filename}"`
      );
    }

    res.status(range ? 206 : 200);
    response.data.pipe(res);

  } catch (err) {
    console.error("Stream error:", err.message);
    res.status(500).send("Failed to fetch video");
  }
});


app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
