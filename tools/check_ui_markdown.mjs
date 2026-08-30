#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const appSource = fs.readFileSync(path.join(root, "src/provision/ui/app.js"), "utf8");
const styleSource = fs.readFileSync(path.join(root, "src/provision/ui/styles.css"), "utf8");

function sourceRange(startMarker, endMarker) {
  const start = appSource.indexOf(startMarker);
  const end = appSource.indexOf(endMarker, start);
  assert.ok(start >= 0, `missing source marker: ${startMarker}`);
  assert.ok(end > start, `missing source marker: ${endMarker}`);
  return appSource.slice(start, end);
}

const context = vm.createContext({
  URL,
  window: { location: { href: "https://provision.test/ui" } }
});
vm.runInContext(
  `${sourceRange("function escapeHtml", "function formatNumber")}
   ${sourceRange("function sessionTitle", "function sessionMeta")}
   ${sourceRange("function splitToolStatusSuffix", "function isControlToolName")}
   ${sourceRange("function compactQuotaPercent", "function renderQuotaBucket")}
   globalThis.markdownApi = {
     normalizeMarkdownSource,
     parseToolActivityText,
     renderMarkdown,
     renderMarkdownInline,
     repairStreamedMarkdownLabel,
     repairStreamedMarkdownProse,
     sessionTitle,
     sessionTabClassName,
     renderCompactQuota
   };`,
  context
);

const {
  normalizeMarkdownSource,
  parseToolActivityText,
  renderMarkdown,
  renderMarkdownInline,
  repairStreamedMarkdownLabel,
  repairStreamedMarkdownProse,
  sessionTitle,
  sessionTabClassName,
  renderCompactQuota
} = context.markdownApi;

let checks = 0;
function equal(actual, expected, label) {
  checks += 1;
  assert.equal(actual, expected, label);
}
function includes(actual, expected, label) {
  checks += 1;
  assert.ok(actual.includes(expected), `${label}\nExpected to include: ${expected}\nActual: ${actual}`);
}
function excludes(actual, expected, label) {
  checks += 1;
  assert.ok(!actual.includes(expected), `${label}\nUnexpected: ${expected}\nActual: ${actual}`);
}

equal(
  renderMarkdown("The API\nremains stable."),
  "<p>The API remains stable.</p>",
  "CommonMark soft lines remain one visual paragraph"
);
equal(
  sessionTitle({ name: "sample-repo", title: "Investigate the rendering bug" }),
  "sample-repo",
  "session tabs prefer the repository name over a provider-generated summary"
);
equal(
  sessionTitle({ display: "~/worktree", title: "Generated summary" }),
  "~/worktree",
  "session tabs fall back to the workspace path before a provider-generated summary"
);
equal(
  sessionTabClassName({ key: "one", active: true }, "two"),
  "session-tab",
  "a live but unselected session does not receive selected-tab highlighting"
);
equal(
  sessionTabClassName({ key: "one", active: false }, "one"),
  "session-tab selected",
  "the selected session receives selected-tab highlighting regardless of liveness"
);
const compactQuotaMarkup = renderCompactQuota({
  state: {
    title: '<img src=x onerror="alert(1)">',
    message: '" onmouseover="alert(1)'
  }
});
includes(compactQuotaMarkup, "&lt;img", "compact quota labels escape server data");
excludes(compactQuotaMarkup, "<img", "compact quota labels never inject HTML");
excludes(compactQuotaMarkup, 'onmouseover="alert(1)', "compact quota attributes escape server data");
excludes(appSource, "quota_compact_html", "WebSocket sessions carry structured compact quota data");
excludes(
  sourceRange("function profileRow", "function providerProfileRow"),
  "_html",
  "profile rows do not accept server-rendered HTML fragments"
);
equal(
  renderMarkdown("The API  \nremains stable."),
  "<p>The API remains stable.</p>",
  "streamed trailing whitespace remains a soft line boundary"
);
equal(
  renderMarkdown("The API\\\nremains stable."),
  "<p>The API<br>remains stable.</p>",
  "a trailing backslash retains an explicit hard break"
);
equal(
  renderMarkdown("First paragraph.\n\nSecond paragraph."),
  "<p>First paragraph.</p><p>Second paragraph.</p>",
  "blank lines retain paragraph boundaries"
);
equal(
  repairStreamedMarkdownProse("private-\nLAN routing"),
  "private-LAN routing",
  "streamed hyphenated acronyms are rejoined"
);
equal(
  renderMarkdown("A non-SSA rule and AOPA-related issue."),
  "<p>A non-SSA rule and AOPA-related issue.</p>",
  "hyphenated acronyms do not become list items"
);
excludes(
  renderMarkdown("A non- SSA rule remains prose."),
  "<ul>",
  "hyphen spacing does not invent a list"
);
equal(renderMarkdown("# Heading"), "<h1>Heading</h1>", "headings render");
equal(
  renderMarkdown("- Alpha\n- Beta"),
  "<ul><li>Alpha</li><li>Beta</li></ul>",
  "unordered lists render"
);
equal(
  renderMarkdown("3. Alpha\n4. Beta"),
  '<ol start="3"><li>Alpha</li><li>Beta</li></ol>',
  "ordered-list start values render"
);
includes(
  renderMarkdown("| Name | Value |\n| --- | --- |\n| AOPA | yes |"),
  "<td>AOPA</td><td>yes</td>",
  "tables render"
);
equal(
  renderMarkdown("```text\nAOPA-* stays literal\n```"),
  '<pre data-language="text"><code>AOPA-* stays literal</code></pre>',
  "fenced code remains literal"
);
includes(renderMarkdownInline("Use `rate_limit_reset`."), "<code>rate_limit_reset</code>", "inline code renders");
includes(renderMarkdownInline("**bold** and *emphasis*"), "<strong>bold</strong>", "strong emphasis renders");
includes(renderMarkdownInline("**bold** and *emphasis*"), "<em>emphasis</em>", "emphasis renders");
includes(renderMarkdownInline("~~removed~~"), "<del>removed</del>", "strikethrough renders");
equal(
  renderMarkdownInline("rate_limit_reset remains literal"),
  "rate_limit_reset remains literal",
  "snake_case identifiers do not trigger emphasis"
);
includes(
  renderMarkdownInline("[Docs](https://example.test/a_(b))"),
  'href="https://example.test/a_(b)"',
  "balanced link destinations render"
);
includes(
  renderMarkdownInline("[daemon.py](/workspace/example/src/provision/daemon.py:1)"),
  '>daemon.py</code>',
  "local file references retain visible labels"
);
includes(
  renderMarkdown("[daemon\n.py]\n(/workspace/example/src/provision/daemon.py:1)"),
  '>daemon.py</code>',
  "streamed local file-reference labels remain visible"
);
equal(
  renderMarkdownInline("[unsafe](javascript:alert(1))"),
  "[unsafe](javascript:alert(1))",
  "unsafe links remain inert text"
);
includes(renderMarkdown("<script>alert(1)</script>"), "&lt;script&gt;", "HTML is escaped");
includes(renderMarkdown("> AOPA\n> remains intact."), "AOPA remains intact.", "blockquote soft lines join");
equal(renderMarkdown("---"), "<hr>", "horizontal rules render");
includes(renderMarkdownInline("mode=xhigh"), "<code>mode=xhigh</code>", "assignments render as code");
equal(
  repairStreamedMarkdownProse("[Provision\nUI]\n(https://example.test/ui)"),
  "[Provision UI](https://example.test/ui)",
  "streamed link words retain their spacing"
);
equal(
  repairStreamedMarkdownProse("[Provision\nUI\nreference]\n(https://example.test/ui)"),
  "[Provision UI reference](https://example.test/ui)",
  "multi-fragment streamed link labels are repaired without empty links"
);
equal(
  renderMarkdown("AOPA  \nAPI and MCP remain intact."),
  "<p>AOPA API and MCP remain intact.</p>",
  "trailing stream whitespace cannot split acronym prose into hard lines"
);
equal(
  renderMarkdown("The transcript included\n>not a Markdown quote."),
  "<p>The transcript included &gt;not a Markdown quote.</p>",
  "an incidental quote marker remains ordinary prose"
);
equal(
  renderMarkdown(">not a Markdown quote."),
  "<p>&gt;not a Markdown quote.</p>",
  "a quote marker without Markdown spacing remains ordinary prose at a block boundary"
);
equal(
  renderMarkdown("The transcript included:\n> A deliberate quotation."),
  "<p>The transcript included:</p><blockquote><p>A deliberate quotation.</p></blockquote>",
  "a quote introduced by a label remains a blockquote"
);
equal(
  renderMarkdown("The transcript included\n> First quoted line.\n> Second quoted line."),
  "<p>The transcript included</p><blockquote><p>First quoted line. Second quoted line.</p></blockquote>",
  "a contiguous quote run remains a blockquote"
);
equal(
  renderMarkdown("The transcript included\n- not a Markdown list."),
  "<p>The transcript included - not a Markdown list.</p>",
  "an incidental list marker remains ordinary prose"
);
equal(
  renderMarkdown("The transcript included:\n- A deliberate list item."),
  "<p>The transcript included:</p><ul><li>A deliberate list item.</li></ul>",
  "a list introduced by a label remains a list"
);
equal(
  renderMarkdown("A latency delta of -5 ms is not a list."),
  "<p>A latency delta of -5 ms is not a list.</p>",
  "negative values never become list items"
);
const inlineMarkdownStyle = styleSource.slice(
  styleSource.indexOf(".control-message-text.markdown code,"),
  styleSource.indexOf(":root[data-theme=\"dark\"] .control-message-text.markdown code,")
);
includes(inlineMarkdownStyle, "overflow-wrap: normal;", "inline Markdown text does not break inside short words");
includes(inlineMarkdownStyle, "hyphens: manual;", "inline Markdown text does not auto-hyphenate acronyms");
excludes(inlineMarkdownStyle, "overflow-wrap: break-word;", "inline Markdown text does not force word fragments across lines");
equal(
  repairStreamedMarkdownLabel("daemon.", "py"),
  "daemon.py",
  "streamed file extensions remain contiguous"
);
equal(
  repairStreamedMarkdownLabel("OpenAI", "API"),
  "OpenAI API",
  "streamed acronym labels remain distinct words"
);
equal(repairStreamedMarkdownProse("x\n\nUnit"), "xUnit", "known streamed xUnit split is repaired");
equal(
  renderMarkdown("The AOPA API\r\nremains stable."),
  "<p>The AOPA API remains stable.</p>",
  "CRLF soft lines normalize"
);
const repairedJsonFence = normalizeMarkdownSource('```json{"ok":true}```');
includes(repairedJsonFence, '```json\n{"ok":true', "collapsed JSON fences open cleanly");
includes(repairedJsonFence, '\n}\n```', "collapsed JSON fences close cleanly");

const parsedOutput = parseToolActivityText(
  "Command: inspect (status completed)\nOutput:\nfirst line\nOutput:\nnested output\ncourt_lines:\n3"
);
equal(parsedOutput.sections.length, 1, "duplicate and arbitrary output labels stay in Output");
equal(parsedOutput.sections[0].label, "Output", "the outer Output section is retained");
includes(parsedOutput.sections[0].text, "Output:\nnested output", "nested Output text is preserved");
includes(parsedOutput.sections[0].text, "court_lines:\n3", "arbitrary colon labels are preserved");

const parsedSections = parseToolActivityText(
  "Tool: web__run (status completed)\nArguments:\nquery\nResult:\nfound"
);
equal(parsedSections.sections.length, 2, "distinct known metadata sections still split");
equal(parsedSections.sections[1].label, "Result", "known Result metadata is recognized");
equal(parsedSections.status, "completed", "tool status metadata is preserved");

let fixtureMessages = 0;
for (const fixturePath of process.argv.slice(2)) {
  const rows = fs.readFileSync(fixturePath, "utf8").split("\n");
  for (const line of rows) {
    if (!line.trim()) continue;
    let row;
    try {
      row = JSON.parse(line);
    } catch {
      continue;
    }
    const payload = row && row.payload;
    if (!payload || typeof payload !== "object" || payload.type !== "message") continue;
    if (!["assistant", "user"].includes(String(payload.role || ""))) continue;
    const content = Array.isArray(payload.content) ? payload.content : [];
    for (const item of content) {
      if (!item || typeof item.text !== "string" || !item.text.trim()) continue;
      const html = renderMarkdown(item.text);
      checks += 1;
      fixtureMessages += 1;
      assert.doesNotMatch(html, /<(a|code|strong|em)(?:\s[^>]*)?><\/\1>/, `${fixturePath}: empty inline Markdown element`);
      assert.doesNotMatch(html, /[A-Z]<br>[A-Z]/, `${fixturePath}: acronym split across a hard break`);
      assert.doesNotMatch(html, /<p>\s*<\/p>/, `${fixturePath}: empty paragraph`);
    }
  }
}

const fixtureSummary = fixtureMessages ? `; ${fixtureMessages} fixture messages rendered` : "";
console.log(`UI Markdown/tool-card checks passed: ${checks}${fixtureSummary}`);
