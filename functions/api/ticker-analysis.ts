// Cloudflare Pages Function — POST /api/ticker-analysis
// Runs an AI-generated research report for a ticker symbol using the
// Anthropic API with the web_search tool enabled.

import Anthropic from "@anthropic-ai/sdk";

interface Env {
  ANTHROPIC_API_KEY: string;
}

interface RequestBody {
  ticker?: string;
}

const SYSTEM_PROMPT = `When given a ticker symbol, run a full analysis covering:
- FUNDAMENTALS: valuation (P/E, market cap, dividend yield if applicable), recent revenue/earnings trends, growth drivers, next earnings date, balance sheet notes.
- TECHNICALS: current price vs key moving averages (20/50/100/200-day), RSI, MACD, ADX/trend strength, key support and resistance levels (not just MA/RSI/MACD).
- SENTIMENT: analyst consensus rating and average price target, recent rating changes, notable recent news.
- SEASONALITY: historical seasonal tendencies for this name or its sector, and any near-term catalysts (earnings, macro events) sitting in the current window.
- SECTOR PEER COMPARISON: brief comparison to 1-2 closest peers on valuation/yield/growth.
- INSIDER ACTIVITY: recent notable insider buying/selling if reported.
- SHORT INTEREST: current short interest % if the name is heavily shorted, or a note that it's not readily available.
- DIRECTIONAL ESTIMATE: a table giving estimated directional bias for the 5-minute, 1-hour, and daily chart timeframes, with brief reasoning for each.

Do not include a "not a financial advisor" disclaimer — this is for the user's own research process, they understand it's not personalized advice.

Format the response in clean markdown suitable for rendering in a web page: use headers, a table for the directional read, and keep it well organized but not padded with filler.`;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export async function onRequestPost(context: {
  request: Request;
  env: Env;
}): Promise<Response> {
  const { request, env } = context;

  if (!env.ANTHROPIC_API_KEY) {
    return jsonResponse(
      { error: "Server is missing ANTHROPIC_API_KEY. Set it as a Cloudflare Pages secret." },
      500,
    );
  }

  let ticker: string;
  try {
    const body = (await request.json()) as RequestBody;
    ticker = (body.ticker || "").trim().toUpperCase();
  } catch {
    return jsonResponse({ error: "Invalid JSON body — expected { ticker: string }." }, 400);
  }

  // Basic validation: plain ticker symbols only (letters, digits, dot, dash),
  // reasonable length cap to avoid abuse.
  if (!ticker || ticker.length > 12 || !/^[A-Z0-9.\-]+$/.test(ticker)) {
    return jsonResponse({ error: "Provide a valid ticker symbol (e.g. NVDA, TQQQ, FTS.TO)." }, 400);
  }

  const client = new Anthropic({ apiKey: env.ANTHROPIC_API_KEY });

  try {
    const response = await client.messages.create({
      model: "claude-sonnet-5",
      max_tokens: 8000,
      thinking: { type: "adaptive" },
      output_config: { effort: "high" },
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: `Analyze ticker: ${ticker}` }],
      tools: [{ type: "web_search_20260209", name: "web_search", max_uses: 10 }],
    });

    if (response.stop_reason === "refusal") {
      return jsonResponse(
        { error: "The analysis request was declined. Try a different ticker or try again." },
        502,
      );
    }

    if (response.stop_reason === "pause_turn") {
      return jsonResponse(
        { error: "The research took too long and was paused mid-search. This usually completes on a retry." },
        504,
      );
    }

    let analysis = "";
    const citations: { url: string; title: string }[] = [];
    const seenUrls = new Set<string>();

    for (const block of response.content) {
      if (block.type === "text") {
        analysis += block.text;
        for (const citation of block.citations ?? []) {
          if (citation.type === "web_search_result_location" && !seenUrls.has(citation.url)) {
            seenUrls.add(citation.url);
            citations.push({ url: citation.url, title: citation.title || citation.url });
          }
        }
      }
    }

    if (!analysis.trim()) {
      return jsonResponse({ error: "The model returned an empty response. Try again." }, 502);
    }

    // Anthropic's web search docs require citing sources when displaying
    // search-derived output directly to end users.
    if (citations.length) {
      analysis += "\n\n## Sources\n" + citations.map((c) => `- [${c.title}](${c.url})`).join("\n");
    }

    return jsonResponse({ analysis });
  } catch (err: unknown) {
    if (err instanceof Anthropic.AuthenticationError) {
      return jsonResponse({ error: "Invalid Anthropic API key configured on the server." }, 500);
    }
    if (err instanceof Anthropic.RateLimitError) {
      return jsonResponse({ error: "Rate limited by Anthropic — try again in a moment." }, 429);
    }
    if (err instanceof Anthropic.APIError) {
      return jsonResponse({ error: `Anthropic API error: ${err.message}` }, 502);
    }
    const message = err instanceof Error ? err.message : "Unexpected server error.";
    return jsonResponse({ error: message }, 500);
  }
}

export async function onRequestGet(): Promise<Response> {
  return jsonResponse({ error: "Use POST with a JSON body: { ticker: string }." }, 405);
}
