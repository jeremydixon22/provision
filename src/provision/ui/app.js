	    const BOOTSTRAP = window.PROVISION_BOOTSTRAP || {};
	    const INITIAL = BOOTSTRAP.initial && typeof BOOTSTRAP.initial === "object" ? BOOTSTRAP.initial : {};
	    const LOGIN_BROWSER_REMOTE_NOTE = String(BOOTSTRAP.loginBrowserRemoteNote || "");
	    const THEME_KEY = "provision-theme";
		    const SUN_ICON = '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2"></path><path d="M12 20v2"></path><path d="m4.93 4.93 1.41 1.41"></path><path d="m17.66 17.66 1.41 1.41"></path><path d="M2 12h2"></path><path d="M20 12h2"></path><path d="m6.34 17.66-1.41 1.41"></path><path d="m19.07 4.93-1.41 1.41"></path></svg>';
		    const MOON_ICON = '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M20.5 14.4A7.5 7.5 0 0 1 9.6 3.5 8.5 8.5 0 1 0 20.5 14.4Z"></path></svg>';
		    const CHART_ICON = '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M3 3v18h18"></path><path d="m7 15 4-4 3 3 5-7"></path><path d="M19 7v5h-5"></path></svg>';
		    const CONTROL_TRANSCRIPT_WINDOW_SIZE = 80;
		    const CONTROL_TRANSCRIPT_WINDOW_STEP = 40;
		    let socket = null;
	    let reconnectTimer = null;
	    let latestStatus = INITIAL.status || {};
	    let latestLiveBusy = Boolean(INITIAL.status && INITIAL.status.live_busy);
	    let latestStats = INITIAL.status && INITIAL.status.stats ? INITIAL.status.stats : { profiles: [], recent: [] };
	    let latestModelCatalog = INITIAL.status && Array.isArray(INITIAL.status.model_catalog) ? INITIAL.status.model_catalog : [];
	    let latestControlPlane = INITIAL.status && INITIAL.status.control_plane ? INITIAL.status.control_plane : { sessions: [] };
	    let latestCodex = INITIAL.status && INITIAL.status.codex ? INITIAL.status.codex : {};
	    let latestPermissions = INITIAL.status && INITIAL.status.permissions ? INITIAL.status.permissions : { pending: [] };
	    let pendingPermissionDecision = "";
	    let pendingRenderPacket = null;
	    let pendingRenderFrame = null;
	    let selectedControlSessionKey = "";
		    let selectedLauncherSessionKey = "";
		    let draggedSessionTabKey = "";
		    let launcherPanelOpen = false;
		    let launcherMode = "new";
		    let launcherPermission = "workspace-write";
		    let launcherResumeSessionId = "";
		    let controlSearchText = "";
		    let controlView = "discussion";
			    let controlPromptHistoryIndex = null;
			    let controlPromptHistorySessionKey = "";
		    let controlPromptHistoryDraft = "";
	    let pendingControlRender = false;
	    let preserveControlScrollOnNextRender = false;
		    let renderedControlScrollKey = "";
		    let controlRenderDeferredAt = 0;
		    let controlRenderDeferTimer = null;
		    let controlTurnSelectInteracting = false;
		    const controlScrollPositions = {};
	    const controlInnerScrollPositions = {};
	    const controlTranscriptWindows = {};
	    const controlTurnPresentations = {};
	    const expandedControlMessages = {};
	    const markdownRenderCache = new Map();
	    const observedTurnCache = {};
	    const observedTurnRequests = {};
	    const historyTurnCache = {};
	    const historyTurnRequests = {};
	    const historyTurnIndexes = {};
	    const historyIndexRequests = {};
	    const resumeCandidateIndexes = {};
	    const resumeCandidateRequests = {};
	    const terminalSnapshotCache = {};
	    const terminalSnapshotRequests = {};
	    let terminalSnapshotRefreshTimer = null;
	    const selectedControlTurnKeys = {};
		    const manuallySelectedControlTurnKeys = {};
	    let mobileDiscussionFocused = false;
	    let mobileComposerFocused = false;
	    let mobileControlDockAnchorY = null;
	    let mobileFocusScrollLockUntil = 0;
	    let mobileTouchStartY = null;
	    const MOBILE_FOCUS_GESTURE_DELTA = 28;
	    const MOBILE_FOCUS_SCROLL_LOCK_MS = 280;
		    const selectedResumeCandidateIds = {};
	    const statsVisibleProfiles = {};
	    let pendingConfirmation = null;
		    let openPinMenuProfile = null;
		    let openModelMenuProfile = null;
	    let openLoginMenuProfile = null;
	    let openReasoningProfile = null;
	    let openReasoningModel = null;
	    let showHiddenProfiles = false;
		    let quotaRefreshTimer = null;
		    let quotaRefreshInFlight = "";
		    const pageDaemonPid = INITIAL.status ? INITIAL.status.pid || null : null;
		    let quotaRefreshDaemonPid = INITIAL.status ? INITIAL.status.pid || null : null;
		    const quotaRefreshQueue = [];
	    const quotaRefreshAttempted = new Set();

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
      })[char]);
    }

	    function normalizeControlMessageTextForDisplay(value, role) {
	      let text = String(value || "").replace(/\r\n?/g, "\n");
	      if (["user", "user_pending", "resume", "context_compaction"].includes(String(role || ""))) {
	        text = text.replace(/^[\s\uFEFF\u200B\u200C\u200D]+|[\s\uFEFF\u200B\u200C\u200D]+$/g, "");
	      }
	      return text;
	    }

	    function isContextCompactionPacket(item) {
	      const role = String(item && item.role || "");
	      if (role === "context_compaction") return true;
	      if (role !== "tool") return false;
	      const text = [item && item.text, item && item.full_text].filter(Boolean).join("\n");
	      return /^(?:Tool|Command):\s*context(?:[ _-]?compaction)\b/im.test(text);
	    }

	    function safeMarkdownHref(value) {
	      const raw = String(value || "").trim();
	      if (!raw) return "";
	      if (raw.startsWith("#")) return escapeHtml(raw);
	      try {
	        const parsed = new URL(raw, window.location.href);
	        if (!["http:", "https:", "mailto:"].includes(parsed.protocol)) return "";
	      } catch {
	        return "";
	      }
	      return escapeHtml(raw);
	    }

	    function isLocalMarkdownFileReference(value) {
	      const raw = String(value || "").trim();
	      return /^(?:file:|\/|~\/|\.{1,2}\/)/i.test(raw);
	    }

	    function markdownLinkLabel(label, href) {
	      const visible = String(label || "").replace(/\s+/g, " ").trim();
	      return visible || String(href || "").trim();
	    }

	    function replaceMarkdownLinks(value, renderLink) {
	      const source = String(value || "");
	      let output = "";
	      let cursor = 0;
	      while (cursor < source.length) {
	        const open = source.indexOf("[", cursor);
	        if (open < 0) return output + source.slice(cursor);
	        const labelEnd = source.indexOf("](", open + 1);
	        if (labelEnd < 0 || source.slice(open + 1, labelEnd).includes("\n") || (open > 0 && source[open - 1] === "!")) {
	          output += source.slice(cursor, open + 1);
	          cursor = open + 1;
	          continue;
	        }
	        const label = source.slice(open + 1, labelEnd);
	        let index = labelEnd + 2;
	        while (/[ \t]/.test(source[index] || "")) index += 1;
	        let href = "";
	        if (source[index] === "<") {
	          const close = source.indexOf(">", index + 1);
	          if (close < 0 || source.slice(index + 1, close).includes("\n")) {
	            output += source.slice(cursor, open + 1);
	            cursor = open + 1;
	            continue;
	          }
	          href = source.slice(index + 1, close);
	          index = close + 1;
	        } else {
	          const hrefStart = index;
	          let depth = 0;
	          while (index < source.length) {
	            const char = source[index];
	            if (char === "\n") break;
	            if (char === "(" ) depth += 1;
	            if (char === ")") {
	              if (depth === 0) break;
	              depth -= 1;
	            }
	            if (depth === 0 && /[ \t]/.test(char)) break;
	            index += 1;
	          }
	          href = source.slice(hrefStart, index);
	        }
	        while (/[ \t]/.test(source[index] || "")) index += 1;
	        if (source[index] === '"' || source[index] === "'") {
	          const quote = source[index];
	          index += 1;
	          while (index < source.length && source[index] !== quote && source[index] !== "\n") index += 1;
	          if (source[index] !== quote) {
	            output += source.slice(cursor, open + 1);
	            cursor = open + 1;
	            continue;
	          }
	          index += 1;
	          while (/[ \t]/.test(source[index] || "")) index += 1;
	        }
	        if (!href || source[index] !== ")") {
	          output += source.slice(cursor, open + 1);
	          cursor = open + 1;
	          continue;
	        }
	        const match = source.slice(open, index + 1);
	        output += source.slice(cursor, open) + renderLink(match, label, href);
	        cursor = index + 1;
	      }
	      return output;
	    }

	    function restoreMarkdownTokens(html, inserts) {
	      return html.replace(/\u0000(\d+)\u0000/g, (_match, index) => inserts[Number(index)] || "");
	    }

	    function renderMarkdownInline(value) {
	      const inserts = [];
	      const token = (html) => {
	        inserts.push(html);
	        return `\u0000${inserts.length - 1}\u0000`;
	      };
	      let text = String(value || "");
	      text = text.replace(/`([^`\n]+)`/g, (_match, code) => (
	        token(`<code>${escapeHtml(code)}</code>`)
	      ));
	      text = replaceMarkdownLinks(text, (match, label, href) => {
	        const rawHref = String(href || "").trim();
	        const visibleLabel = markdownLinkLabel(label, rawHref);
	        if (isLocalMarkdownFileReference(rawHref)) {
	          return token(`<code class="markdown-file-ref" title="${escapeHtml(rawHref)}">${escapeHtml(visibleLabel)}</code>`);
	        }
	        const safeHref = safeMarkdownHref(rawHref);
	        if (!safeHref) {
	          return match;
	        }
	        return token(`<a href="${safeHref}" target="_blank" rel="noreferrer">${renderMarkdownInline(visibleLabel)}</a>`);
	      });
	      text = text.replace(/(^|[\s([{,;])([A-Za-z_][A-Za-z0-9_.-]*=[A-Za-z0-9_./:-]+)/g, (_match, prefix, assignment) => (
	        `${prefix}${token(`<code>${escapeHtml(assignment)}</code>`)}`
	      ));
	      let html = escapeHtml(text);
	      html = html.replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>");
	      html = html.replace(/__([^_\n]+)__/g, "<strong>$1</strong>");
	      html = html.replace(/~~([^~\n]+)~~/g, "<del>$1</del>");
	      html = html.replace(/(^|[\s(])\*([^*\n]+)\*(?=$|[\s).,;:!?])/g, "$1<em>$2</em>");
	      html = html.replace(/(^|[\s(])_([^_\n]+)_(?=$|[\s).,;:!?])/g, "$1<em>$2</em>");
	      return restoreMarkdownTokens(html, inserts);
	    }

	    function renderMarkdownInlineLines(lines) {
	      return lines.map((rawLine, index) => {
	        const line = String(rawLine || "");
	        const hardBreak = /(?: {2,}|\\)$/.test(line);
	        const content = hardBreak ? line.replace(/(?: {2,}|\\)$/, "") : line;
	        const rendered = renderMarkdownInline(content.trim());
	        if (index === lines.length - 1) return rendered;
	        return `${rendered}${hardBreak ? "<br>" : " "}`;
	      }).join("");
	    }

	    function parseJsonControlMessage(value) {
	      const text = String(value || "").trim();
	      if (!text || !/^[{[]/.test(text) || !/[}\]]$/.test(text)) return null;
	      try {
	        return JSON.parse(text);
	      } catch {
	        return null;
	      }
	    }

	    function renderMarkdownCodeBlock(value, language = "") {
	      const lang = language ? ` data-language="${escapeHtml(language)}"` : "";
	      return `<pre${lang}><code>${escapeHtml(value)}</code></pre>`;
	    }

	    function renderJsonControlMessage(value) {
	      const parsed = parseJsonControlMessage(value);
	      if (parsed === null) return "";
	      return renderMarkdownCodeBlock(JSON.stringify(parsed, null, 2), "json");
	    }

	    function cachedMarkdownRender(cacheKey, renderer) {
	      if (markdownRenderCache.has(cacheKey)) {
	        const value = markdownRenderCache.get(cacheKey);
	        markdownRenderCache.delete(cacheKey);
	        markdownRenderCache.set(cacheKey, value);
	        return value;
	      }
	      const value = renderer();
	      markdownRenderCache.set(cacheKey, value);
	      while (markdownRenderCache.size > 600) {
	        const first = markdownRenderCache.keys().next().value;
	        markdownRenderCache.delete(first);
	      }
	      return value;
	    }

		    function repairStreamedMarkdownLabel(left, right) {
		      const before = String(left || "").trim();
		      const after = String(right || "").trim();
		      const compactBoundary = /[./_:@#-]$/.test(before) || /^[./_:@#-]/.test(after);
		      return compactBoundary ? `${before}${after}` : `${before} ${after}`;
		    }

		    function repairStreamedMarkdownProse(value) {
		      let source = String(value || "");
		      source = source.replace(/\[\s*\n{2,}\s*([^\]\n]{1,160}?)\s*\]/g, (_match, label) => `[${label.trim()}]`);
		      source = source.replace(/\[([^\]\n]{1,120}?)\s*\n+\s*([^\]\n]{1,120}?)\]/g, (_match, left, right) => {
		        const label = repairStreamedMarkdownLabel(left, right);
		        return label.length <= 180 ? `[${label}]` : _match;
		      });
		      source = source.replace(/\]\s*\n+\s*\(([^)\n]{1,500})\)/g, (_match, href) => `](${href.trim()})`);
		      source = source.replace(/([A-Za-z0-9])-\n+(?=[A-Za-z0-9])/g, "$1-");
		      source = source.replace(/\bx\n{2,}Unit\b/g, "xUnit");
		      return source;
		    }

		    function repairStreamedMarkdownSource(value) {
		      const lines = String(value || "").replace(/\r\n?/g, "\n").split("\n");
		      const rendered = [];
		      let prose = [];
		      let inFence = false;
		      const flushProse = () => {
		        if (!prose.length) return;
		        rendered.push(...repairStreamedMarkdownProse(prose.join("\n")).split("\n"));
		        prose = [];
		      };
		      for (const rawLine of lines) {
		        const tildeFence = rawLine.match(/^(\s*)~~~([A-Za-z0-9_.+-]*)\s*$/);
		        const line = tildeFence ? `${tildeFence[1]}\`\`\`${tildeFence[2]}` : rawLine;
		        if (/^\s*```/.test(line)) {
		          flushProse();
		          rendered.push(line);
		          inFence = !inFence;
		          continue;
		        }
		        if (inFence) rendered.push(line);
		        else prose.push(line);
		      }
		      flushProse();
		      return rendered.join("\n");
		    }

	    function normalizeMarkdownSource(value) {
	      const lines = repairStreamedMarkdownSource(value).split("\n");
	      let inFence = false;
	      let fenceLanguage = "";
	      let repairFenceLines = false;
	      let passthroughMarkdownFence = false;
	      let yamlRepairStack = [];
	      let jsonRepairIndent = 0;
	      const normalizeFenceCodeLine = (line, lang) => {
	        const raw = String(line || "");
	        if (/^json$/i.test(lang)) {
	          const rendered = [];
	          for (const rawLine of raw.split("\n")) {
	            let text = rawLine.trim();
	            if (!text) {
	              rendered.push("");
	              continue;
	            }
	            const trailingClosers = [];
	            while (!/^[}\]],?$/.test(text)) {
	              const closeMatch = text.match(/^(.*\S)\s*([}\]])(,?)$/);
	              if (!closeMatch) break;
	              text = closeMatch[1].trimEnd();
	              trailingClosers.unshift(`${closeMatch[2]}${closeMatch[3] || ""}`);
	            }
	            while (/^[}\]]/.test(text)) {
	              jsonRepairIndent = Math.max(0, jsonRepairIndent - 1);
	              const close = text.slice(0, text[1] === "," ? 2 : 1);
	              rendered.push(`${" ".repeat(jsonRepairIndent * 2)}${close}`);
	              text = text.slice(close.length).trim();
	            }
	            if (text) {
	              rendered.push(`${" ".repeat(jsonRepairIndent * 2)}${text}`);
	              if (/[{[]\s*,?$/.test(text)) {
	                jsonRepairIndent += 1;
	              }
	            }
	            for (const close of trailingClosers) {
	              jsonRepairIndent = Math.max(0, jsonRepairIndent - 1);
	              rendered.push(`${" ".repeat(jsonRepairIndent * 2)}${close}`);
	            }
	          }
	          return rendered.join("\n");
	        }
	        if (/^(?:yaml|yml)$/i.test(lang)) {
	          const matches = Array.from(raw.matchAll(/[A-Za-z_][A-Za-z0-9_-]*:/g));
	          if (!matches.length) return raw;
	          const parentKeys = new Set(["launcher", "quota", "resume", "metadata"]);
	          const rendered = [];
	          for (let index = 0; index < matches.length; index += 1) {
	            const match = matches[index];
	            const next = matches[index + 1];
	            const segment = raw.slice(match.index, next ? next.index : undefined).trim();
	            const colon = segment.indexOf(":");
	            if (colon < 0) continue;
	            const key = segment.slice(0, colon).trim();
	            const value = segment.slice(colon + 1).trim();
	            let indent = Math.max(0, yamlRepairStack.length) * 2;
	            if (!value) {
	              if (!yamlRepairStack.length || key === "session") {
	                indent = 0;
	                yamlRepairStack = [key];
	              } else if (parentKeys.has(key) && yamlRepairStack[0] === "session") {
	                indent = 2;
	                yamlRepairStack = ["session", key];
	              } else {
	                yamlRepairStack.push(key);
	              }
	            }
	            rendered.push(`${" ".repeat(indent)}${key}:${value ? ` ${value}` : ""}`);
	          }
	          return rendered.join("\n");
	        }
	        if (/^(?:text|txt)$/i.test(lang)) {
	          return raw.replace(/(\S)(\d{2}:\d{2}:\d{2}\s+)/g, "$1\n$2");
	        }
	        return raw;
	      };
	      const normalizeLine = (line, options = {}) => {
	        let normalized = line;
	        if (options.markdownPassthrough) {
	          normalized = normalized.replace(/\s*```\s*$/, "");
	          normalized = normalized.replace(/^(#{1,4}\s+)([A-Z][A-Za-z0-9_./:+ -]*?)-\s+([A-Z0-9].*)$/, "$1$2\n\n- $3");
	          normalized = normalized.replace(/^(#{1,4}\s+)([A-Z][A-Za-z0-9_./:+-]*?)([A-Z][a-z].*)$/, "$1$2\n\n$3");
	        }
	        normalized = normalized.replace(/^(#{1,4}\s+.*?)(Working directory:\s*)/i, "$1\n\n$2");
	        normalized = normalized.replace(/(Working directory:\s+.*?)(Current status:)/i, "$1\n\n$2");
	        normalized = normalized.replace(/([^#\n])\s*(#{1,4}\s+\S)/g, "$1\n\n$2");
	        normalized = normalized.replace(/([^\n])\s*([-*+]\s+\[[ xX]\]\s+\S)/g, "$1\n$2");
	        normalized = normalized.replace(/([^\n])\s*([-*+]\s+\*\*\S)/g, "$1\n$2");
		        normalized = normalized.replace(/([.!?:])\s*([-*+]\s+\S)/g, "$1\n$2");
		        normalized = normalized.replace(/([.!?:])\s*-(\d+)(\s+\S.*)$/g, "$1\n- $2$3");
	        normalized = normalized.replace(/^(\s*)-(\d+)(\s+\S.*)$/g, "$1- $2$3");
	        return normalized;
	      };
	      return lines.map((line) => {
	        const malformedFence = !inFence
	          ? line.match(/^\s*```(markdown|md|json|yaml|yml|toml|ini|bash|sh|shell|python|py|javascript|js|typescript|ts|html|css|xml|sql|text|txt)(?=\S)(.*)$/i)
	          : null;
	        if (malformedFence) {
	          const lang = malformedFence[1] || "";
	          const rest = malformedFence[2] || "";
	          if (/^(?:md|markdown)$/i.test(lang)) {
	            passthroughMarkdownFence = true;
	            return normalizeLine(rest, { markdownPassthrough: true });
	          }
	          inFence = true;
	          fenceLanguage = lang;
	          repairFenceLines = true;
	          yamlRepairStack = [];
	          jsonRepairIndent = 0;
	          const trailingFence = rest.match(/^(.*\S)\s*```\s*$/);
	          if (trailingFence) {
	            inFence = false;
	            fenceLanguage = "";
	            repairFenceLines = false;
	            const repaired = normalizeFenceCodeLine(trailingFence[1], lang);
	            yamlRepairStack = [];
	            jsonRepairIndent = 0;
	            return `\`\`\`${lang}\n${repaired}\n\`\`\``;
	          }
	          return `\`\`\`${lang}\n${normalizeFenceCodeLine(rest, lang)}`;
	        }
	        if (passthroughMarkdownFence) {
	          if (/^\s*```\s*$/.test(line)) {
	            passthroughMarkdownFence = false;
	            return "";
	          }
	          const trailingFence = line.match(/^(.*\S)\s*```\s*$/);
	          if (trailingFence) {
	            passthroughMarkdownFence = false;
	            return normalizeLine(trailingFence[1], { markdownPassthrough: true });
	          }
	          return normalizeLine(line, { markdownPassthrough: true });
	        }
	        if (/^\s*```/.test(line)) {
	          inFence = !inFence;
	          fenceLanguage = inFence ? (line.trim().match(/^```([A-Za-z0-9_.+-]*)/) || [])[1] || "" : "";
	          repairFenceLines = false;
	          yamlRepairStack = [];
	          jsonRepairIndent = 0;
	          return line;
	        }
	        if (inFence) {
	          const trailingFence = line.match(/^(.*\S)\s*```\s*$/);
	          if (trailingFence) {
	            inFence = false;
	            const repaired = repairFenceLines
	              ? normalizeFenceCodeLine(trailingFence[1], fenceLanguage)
	              : trailingFence[1];
	            fenceLanguage = "";
	            repairFenceLines = false;
	            yamlRepairStack = [];
	            jsonRepairIndent = 0;
	            return `${repaired}\n\`\`\``;
	          }
	          return repairFenceLines ? normalizeFenceCodeLine(line, fenceLanguage) : line;
	        }
	        return normalizeLine(line);
	      }).join("\n");
	    }

	    function markdownBlockStarts(lines, index) {
	      const line = lines[index] || "";
	      const next = lines[index + 1] || "";
	      return (
	        /^```/.test(line.trim())
	        || /^\s{0,3}#{1,4}\s+/.test(line)
	        || /^\s{0,3}>\s?/.test(line)
	        || /^\s*([-*+])\s+/.test(line)
	        || /^\s*\d+\.\s+/.test(line)
	        || /^\s{0,3}[-*_](?:\s*[-*_]){2,}\s*$/.test(line)
	        || markdownTableStarts(line, next)
	      );
	    }

	    function markdownTableStarts(line, next) {
	      return line.includes("|") && /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(next || "");
	    }

	    function markdownTableCells(line) {
	      let text = String(line || "").trim();
	      if (text.startsWith("|")) text = text.slice(1);
	      if (/(?:^|[^\\])(?:\\\\)*\|$/.test(text)) text = text.slice(0, -1);
	      const cells = [];
	      let cell = "";
	      let escaped = false;
	      let codeTickCount = 0;
	      for (let index = 0; index < text.length; index += 1) {
	        const char = text[index];
	        if (char === "\\" && !escaped) {
	          escaped = true;
	          cell += char;
	          continue;
	        }
	        if (char === "`" && !escaped) {
	          let run = 1;
	          while (text[index + run] === "`") run += 1;
	          if (!codeTickCount) codeTickCount = run;
	          else if (codeTickCount === run) codeTickCount = 0;
	          cell += text.slice(index, index + run);
	          index += run - 1;
	          continue;
	        }
	        if (char === "|" && !escaped && !codeTickCount) {
	          cells.push(cell.trim().replace(/\\\|/g, "|"));
	          cell = "";
	          continue;
	        }
	        cell += char;
	        escaped = false;
	      }
	      cells.push(cell.trim().replace(/\\\|/g, "|"));
	      return cells;
	    }

	    function renderMarkdownTable(lines, index) {
	      const headers = markdownTableCells(lines[index]);
	      let cursor = index + 2;
	      const rows = [];
	      while (cursor < lines.length && lines[cursor].includes("|") && lines[cursor].trim()) {
	        rows.push(markdownTableCells(lines[cursor]));
	        cursor += 1;
	      }
	      const head = headers.map((cell) => `<th>${renderMarkdownInline(cell)}</th>`).join("");
	      const body = rows.map((row) => (
	        `<tr>${headers.map((_header, cellIndex) => `<td>${renderMarkdownInline(row[cellIndex] || "")}</td>`).join("")}</tr>`
	      )).join("");
	      return {
	        html: `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`,
	        index: cursor
	      };
	    }

	    function markdownIndentedCodeLines(lines, index) {
	      const codeLines = [];
	      let cursor = index;
	      while (cursor < lines.length && (/^(?: {4}|\t)/.test(lines[cursor]) || !lines[cursor].trim())) {
	        if (!lines[cursor].trim()) {
	          codeLines.push("");
	        } else {
	          codeLines.push(lines[cursor].replace(/^(?: {4}|\t)/, ""));
	        }
	        cursor += 1;
	      }
	      while (codeLines.length && !codeLines[codeLines.length - 1]) codeLines.pop();
	      return { codeLines, index: cursor };
	    }

	    function markdownIndentedCodeLooksIntentional(codeLines) {
	      const meaningful = codeLines.map((line) => line.trim()).filter(Boolean);
	      if (!meaningful.length) return false;
	      const strongCodeLine = meaningful.some((line) => (
	        /^[$>#]\s+/.test(line)
	        || /\s--?[A-Za-z0-9][\w-]*/.test(line)
	        || /(?:[{}[\];=]|=>|<\/?\w|&&|\|\|)/.test(line)
	      ));
	      const commandShaped = meaningful.every((line) => (
	        /^[A-Za-z0-9_./-]+(?:\s+[A-Za-z0-9_./:-]+){0,8}$/.test(line)
	      ));
	      const proseLike = meaningful.some((line) => (
	        line.split(/\s+/).length >= 10
	        && /[,.!?;:]/.test(line)
	        && !/\s--?[A-Za-z0-9][\w-]*/.test(line)
	      ));
	      return !proseLike && (strongCodeLine || (meaningful.length <= 4 && commandShaped));
	    }

	    function renderMarkdown(value) {
	      const lines = normalizeMarkdownSource(value).split("\n");
	      const blocks = [];
	      let index = 0;
	      while (index < lines.length) {
	        const line = lines[index];
	        const trimmed = line.trim();
	        if (!trimmed) {
	          index += 1;
	          continue;
	        }
	        if (/^(?: {4}|\t)/.test(line)) {
	          const rendered = markdownIndentedCodeLines(lines, index);
	          if (markdownIndentedCodeLooksIntentional(rendered.codeLines)) {
	            blocks.push(`<pre><code>${escapeHtml(rendered.codeLines.join("\n"))}</code></pre>`);
	            index = rendered.index;
	            continue;
	          }
	        }
	        const fence = trimmed.match(/^```([A-Za-z0-9_.+-]*)\s*$/);
	        if (fence) {
	          const codeLines = [];
	          index += 1;
	          while (index < lines.length && !/^```\s*$/.test(lines[index].trim())) {
	            codeLines.push(lines[index]);
	            index += 1;
	          }
	          if (index < lines.length) index += 1;
	          blocks.push(renderMarkdownCodeBlock(codeLines.join("\n"), fence[1] || ""));
	          continue;
	        }
	        const heading = line.match(/^\s{0,3}(#{1,4})\s+(.+)$/);
	        if (heading) {
	          const level = heading[1].length;
	          blocks.push(`<h${level}>${renderMarkdownInline(heading[2].trim())}</h${level}>`);
	          index += 1;
	          continue;
	        }
	        if (/^\s{0,3}[-*_](?:\s*[-*_]){2,}\s*$/.test(line)) {
	          blocks.push("<hr>");
	          index += 1;
	          continue;
	        }
	        if (markdownTableStarts(line, lines[index + 1] || "")) {
	          const rendered = renderMarkdownTable(lines, index);
	          blocks.push(rendered.html);
	          index = rendered.index;
	          continue;
	        }
	        if (/^\s{0,3}>\s?/.test(line)) {
	          const quoteLines = [];
	          while (index < lines.length && /^\s{0,3}>\s?/.test(lines[index])) {
	            quoteLines.push(lines[index].replace(/^\s{0,3}>\s?/, ""));
	            index += 1;
	          }
	          blocks.push(`<blockquote>${renderMarkdown(quoteLines.join("\n"))}</blockquote>`);
	          continue;
	        }
	        const unordered = line.match(/^\s*([-*+])\s+(.+)$/);
	        const ordered = line.match(/^\s*(\d+)\.\s+(.+)$/);
	        if (unordered || ordered) {
	          const listTag = ordered ? "ol" : "ul";
	          const start = ordered ? Math.max(1, Number(ordered[1] || 1)) : 1;
	          const items = [];
	          while (index < lines.length) {
	            const current = lines[index];
	            const itemMatch = listTag === "ol"
	              ? current.match(/^\s*\d+\.\s+(.+)$/)
	              : current.match(/^\s*[-*+]\s+(.+)$/);
	            if (!itemMatch) {
	              if (!current.trim() && index + 1 < lines.length) {
	                const next = lines[index + 1] || "";
	                const nextItem = listTag === "ol"
	                  ? next.match(/^\s*\d+\.\s+(.+)$/)
	                  : next.match(/^\s*[-*+]\s+(.+)$/);
	                if (nextItem) {
	                  index += 1;
	                  continue;
	                }
	              }
	              break;
	            }
	            const itemLines = [itemMatch[1]];
	            index += 1;
	            while (index < lines.length && /^\s{2,}\S/.test(lines[index]) && !markdownBlockStarts(lines, index)) {
		              itemLines.push(lines[index].trimStart());
	              index += 1;
	            }
		            items.push(`<li>${renderMarkdownInlineLines(itemLines)}</li>`);
	          }
	          const startAttr = listTag === "ol" && start > 1 ? ` start="${start}"` : "";
	          blocks.push(`<${listTag}${startAttr}>${items.join("")}</${listTag}>`);
	          continue;
	        }
	        const paragraph = [];
	        while (index < lines.length && lines[index].trim() && !markdownBlockStarts(lines, index)) {
		          paragraph.push(lines[index].trimStart());
	          index += 1;
	        }
	        if (paragraph.length) {
		          blocks.push(`<p>${renderMarkdownInlineLines(paragraph)}</p>`);
	        } else {
	          index += 1;
	        }
	      }
	      return blocks.join("");
	    }

	    function formatNumber(value) {
	      return Number(value || 0).toLocaleString();
	    }

	    function formatBytes(value) {
	      const bytes = Number(value || 0);
	      if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
	      if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	      return `${bytes} B`;
	    }

	    function formatEventTime(value) {
	      if (!value) return "";
	      const date = new Date(value);
	      if (Number.isNaN(date.getTime())) return String(value);
	      return date.toLocaleString([], {
	        month: "short",
	        day: "numeric",
	        hour: "2-digit",
	        minute: "2-digit"
	      });
	    }

	    function signedPercent(value) {
	      const number = Number(value);
	      if (!Number.isFinite(number)) return "";
	      const sign = number > 0 ? "+" : "";
	      return `${sign}${number.toFixed(Math.abs(number) < 1 && number !== 0 ? 1 : 0)}%`;
	    }

	    function quotaDeltaText(quota) {
	      if (!quota || typeof quota !== "object") return "";
	      const pieces = [];
	      for (const [name, row] of Object.entries(quota)) {
	        if (!row || typeof row !== "object") continue;
	        const primaryDelta = signedPercent(row.primary_delta_percent);
	        const weeklyDelta = signedPercent(row.weekly_delta_percent);
	        const primary = row.primary_remaining_percent;
	        const weekly = row.weekly_remaining_percent;
	        const bits = [];
	        if (primaryDelta) bits.push(`5h ${primaryDelta}`);
	        if (weeklyDelta) bits.push(`weekly ${weeklyDelta}`);
	        if (!bits.length && Number.isFinite(Number(primary))) bits.push(`5h ${Number(primary).toFixed(0)}%`);
	        if (!bits.length && Number.isFinite(Number(weekly))) bits.push(`weekly ${Number(weekly).toFixed(0)}%`);
	        if (bits.length) pieces.push(`${name}: ${bits.join(", ")}`);
	      }
	      return pieces.join("; ");
	    }

	    function statsEventText(event) {
	      const type = String(event.type || "");
	      const profile = String(event.profile || "unknown");
	      if (type === "token_usage") {
	        return `${profile} token usage: ${formatNumber(event.tokens)}${event.fast ? " fast" : ""}`;
	      }
	      if (type === "websocket_tunnel") {
	        return `${profile} tunnel closed: ${formatBytes(event.bytes)}`;
	      }
	      if (type === "http_request") {
	        const status = event.status ? `status ${event.status}` : "status unknown";
	        return `${profile} ${event.path || "request"} ${status}`;
	      }
	      if (type === "quota_update") {
	        const movement = quotaDeltaText(event.quota);
	        const suffix = movement ? `: ${movement}` : "";
	        return `${profile} quota update${event.source ? ` from ${event.source}` : ""}${event.fast ? " while fast" : ""}${suffix}`;
	      }
	      if (type === "reset_credit") {
	        return `${profile} reset credit: ${event.outcome || "unknown"}`;
	      }
	      return `${profile} ${type || "event"}`;
	    }

	    function scrollSnapshot(element) {
	      if (!element) return null;
	      return {
	        top: element.scrollTop,
	        atBottom: element.scrollHeight - element.scrollTop - element.clientHeight < 24
	      };
	    }

	    function restoreScrollSnapshot(element, snapshot) {
	      if (!element || !snapshot) return;
	      element.scrollTop = snapshot.atBottom
	        ? Math.max(0, element.scrollHeight - element.clientHeight)
	        : snapshot.top;
	    }

	    function formatAge(seconds) {
	      const value = Number(seconds);
	      if (!Number.isFinite(value)) return "";
	      if (value < 60) return `${Math.max(0, Math.round(value))}s`;
	      if (value < 3600) return `${Math.round(value / 60)}m`;
	      return `${(value / 3600).toFixed(1)}h`;
	    }

	    function controlPlane(status) {
	      return status && status.control_plane && typeof status.control_plane === "object"
	        ? status.control_plane
	        : latestControlPlane || { sessions: [] };
	    }

	    function controlSessions(status) {
	      const plane = controlPlane(status);
	      return Array.isArray(plane.sessions) ? plane.sessions : [];
	    }

	    function sessionTitle(session) {
	      // Tabs identify the workspace, not a provider-generated conversation
	      // summary. Native titles remain available as session metadata.
	      return String(session.name || session.display || session.cwd || session.title || "Session");
	    }

	    function sessionMeta(session) {
	      const pieces = [];
	      if (session.provider) pieces.push(String(session.provider));
	      if (session.pinned_profile) pieces.push(`pinned ${session.pinned_profile}`);
	      else if (session.provider_profile) pieces.push(`profile ${session.provider_profile}`);
	      else if (session.last_profile) pieces.push(`last ${session.last_profile}`);
	      const active = Number(session.active_requests || 0);
	      const pending = Number(session.pending_websocket_work || 0);
	      const tunnels = Number(session.active_tunnels || 0);
	      if (active) pieces.push(`${active} request${active === 1 ? "" : "s"}`);
	      if (pending) pieces.push(`${pending} turn${pending === 1 ? "" : "s"}`);
	      else if (tunnels) pieces.push(`${tunnels} tunnel${tunnels === 1 ? "" : "s"}`);
	      return pieces.join(" / ") || String(session.display || session.cwd || "idle");
	    }

	    function updateControlDockGeometry() {
	      const modal = document.getElementById("controlModal");
	      const tabs = document.getElementById("sessionTabs");
	      if (!modal || !tabs) return;
	      const top = tabs.offsetTop + tabs.offsetHeight + 8;
	      modal.style.setProperty("--control-dock-top", `${Math.max(0, top)}px`);
	      const launcher = document.getElementById("launcherBar");
	      if (launcher) launcher.style.setProperty("--control-dock-top", `${Math.max(0, top)}px`);
		      const stats = document.getElementById("statsModal");
		      if (stats) {
		        const tabsTop = tabs.getBoundingClientRect().top;
		        stats.style.setProperty("--stats-modal-top", `${Math.max(0, tabsTop)}px`);
	      }
	      updateMobileControlChromeGeometry();
	      updateMobileControlStickiness();
	    }

	    function controlScrollKey() {
	      const turn = selectedControlTurnKeys[selectedControlSessionKey || ""] || "";
	      return `${selectedControlSessionKey || "none"}:${controlView || "discussion"}:${turn}:${controlSearchText || ""}`;
	    }

	    function controlTranscriptWindowKey() {
	      const turn = selectedControlTurnKeys[selectedControlSessionKey || ""] || "";
	      return `${selectedControlSessionKey || "none"}:${turn}:${controlSearchText || ""}`;
	    }

		    function controlTranscriptWindow(total) {
		      if (total <= CONTROL_TRANSCRIPT_WINDOW_SIZE) {
		        return { start: 0, end: total };
		      }
		      const key = controlTranscriptWindowKey();
		      const existing = controlTranscriptWindows[key];
		      if (!existing) {
		        const start = Math.max(0, total - CONTROL_TRANSCRIPT_WINDOW_SIZE);
		        const value = { start, end: total, previousTotal: total };
		        controlTranscriptWindows[key] = value;
		        return value;
		      }
		      if (total > existing.previousTotal && existing.end >= existing.previousTotal) {
		        const delta = total - existing.previousTotal;
		        existing.end = total;
		        existing.start = Math.max(0, existing.start + delta);
		      }
		      existing.start = Math.max(0, Math.min(existing.start, total - 1));
		      existing.end = Math.max(existing.start + 1, Math.min(existing.end, total));
		      existing.previousTotal = total;
		      return existing;
		    }

		    function expandControlTranscriptWindow(direction) {
		      const key = controlTranscriptWindowKey();
		      const current = controlTranscriptWindows[key];
		      if (!current) return false;
		      const oldStart = current.start;
		      const oldEnd = current.end;
		      const total = Number(current.previousTotal || 0);
		      if (direction === "above") {
		        current.start = Math.max(0, current.start - CONTROL_TRANSCRIPT_WINDOW_STEP);
		      } else {
		        current.end = Math.min(total, current.end + CONTROL_TRANSCRIPT_WINDOW_STEP);
		      }
		      return oldStart !== current.start || oldEnd !== current.end;
		    }

	    function saveControlScroll() {
	      const content = document.getElementById("controlContent");
	      if (!content) return;
	      const key = renderedControlScrollKey || controlScrollKey();
	      controlScrollPositions[key] = content.scrollTop;
	    }

	    function saveControlInnerScroll() {
	      const content = document.getElementById("controlContent");
	      if (!content) return;
	      const prefix = renderedControlScrollKey || controlScrollKey();
	      content.querySelectorAll("[data-control-inner-scroll]").forEach((element) => {
	        const key = element.dataset.controlInnerScroll || "";
	        if (!key) return;
	        controlInnerScrollPositions[`${prefix}::${key}`] = element.scrollTop;
	      });
	    }

	    function restoreControlScroll() {
	      const content = document.getElementById("controlContent");
	      if (!content) return;
	      const top = controlScrollPositions[controlScrollKey()];
	      if (typeof top === "number") content.scrollTop = top;
	    }

	    function restoreControlInnerScroll() {
	      const content = document.getElementById("controlContent");
	      if (!content) return;
	      const prefix = controlScrollKey();
	      content.querySelectorAll("[data-control-inner-scroll]").forEach((element) => {
	        const key = element.dataset.controlInnerScroll || "";
	        const top = controlInnerScrollPositions[`${prefix}::${key}`];
	        if (typeof top === "number") element.scrollTop = top;
	      });
	    }

	    function controlContentAtBottom(content) {
	      if (!content) return true;
	      return content.scrollHeight - content.scrollTop - content.clientHeight < 24;
	    }

		    function updateControlScrollBadges() {
		      const content = document.getElementById("controlContent");
		      if (!content || controlView !== "discussion") return;
		      const transcript = content.querySelector(".control-transcript");
		      const topBadge = content.querySelector("[data-control-scroll='above']");
		      const bottomBadge = content.querySelector("[data-control-scroll='below']");
		      if (!transcript || !topBadge || !bottomBadge) return;
		      const bounds = content.getBoundingClientRect();
		      const hiddenAbove = Number(transcript.dataset.hiddenAbove || 0);
		      const hiddenBelow = Number(transcript.dataset.hiddenBelow || 0);
		      let visibleAbove = 0;
		      let visibleBelow = 0;
		      for (const item of transcript.querySelectorAll(".control-message[data-transcript-index]")) {
		        const itemBounds = item.getBoundingClientRect();
		        if (itemBounds.bottom < bounds.top + 8) visibleAbove += 1;
		        if (itemBounds.top > bounds.bottom - 8) visibleBelow += 1;
		      }
		      const above = hiddenAbove + visibleAbove;
		      const below = hiddenBelow + visibleBelow;
		      topBadge.hidden = above <= 0;
		      bottomBadge.hidden = below <= 0;
		      topBadge.textContent = `${above} above`;
		      bottomBadge.textContent = `${below} below`;
		      topBadge.title = hiddenAbove > 0 ? `Show older hidden transcript entries (${hiddenAbove} hidden)` : "Scroll upward";
		      bottomBadge.title = hiddenBelow > 0 ? `Show newer hidden transcript entries (${hiddenBelow} hidden)` : "Scroll downward";
		    }

	    function controlSelectionActive() {
	      const modal = document.getElementById("controlModal");
	      const selection = window.getSelection ? window.getSelection() : null;
	      if (!modal || !selection || selection.isCollapsed || !selection.rangeCount) return false;
	      const anchor = selection.anchorNode && selection.anchorNode.nodeType === Node.ELEMENT_NODE
	        ? selection.anchorNode
	        : selection.anchorNode ? selection.anchorNode.parentElement : null;
	      const focus = selection.focusNode && selection.focusNode.nodeType === Node.ELEMENT_NODE
	        ? selection.focusNode
	        : selection.focusNode ? selection.focusNode.parentElement : null;
	      return Boolean((anchor && modal.contains(anchor)) || (focus && modal.contains(focus)));
	    }

	    function controlRenderShouldDefer() {
	      return controlSelectionActive();
	    }

	    function flushPendingControlRender() {
	      if (!pendingControlRender || controlRenderShouldDefer()) return;
	      renderControlModal(true);
	    }

	    function scheduleControlRenderFlush() {
	      if (controlRenderDeferTimer) return;
	      controlRenderDeferTimer = setTimeout(() => {
	        controlRenderDeferTimer = null;
	        if (pendingControlRender) renderControlModal(true);
	      }, 2050);
	    }

	    function renderSessionTabs(status) {
	      const container = document.getElementById("sessionTabs");
	      if (!container) return;
	      const sessions = controlSessions(status);
	      const launchSelected = launcherPanelOpen ? " selected" : "";
	      const launchTab = `
	        <button class="session-tab launch-tab${launchSelected}" type="button" data-launch-tab="1" title="Launch a Codex CLI session">
	          <span class="session-tab-title">+</span>
	          <span class="session-tab-meta">Codex</span>
	        </button>
	      `;
	      if (!sessions.length) {
	        selectedControlSessionKey = "";
	        container.innerHTML = '<div class="session-tabs-empty">No Provision-managed CLI sessions observed yet</div>' + launchTab;
	        resetMobileDiscussionFocus();
	        syncDiscussionPaneVisibility();
	        renderMobileControlStatus(null);
	        updateControlDockGeometry();
	        return;
	      }
	      if (selectedControlSessionKey && !sessions.some((session) => session.key === selectedControlSessionKey)) {
	        selectedControlSessionKey = "";
	        resetMobileDiscussionFocus();
	        renderMobileControlStatus(null);
	      }
	      container.innerHTML = sessions.map((session) => {
	        const key = String(session.key || "");
	        const active = session.active ? " active" : "";
	        const selected = key && key === selectedControlSessionKey ? " selected" : "";
	        return `
          <button class="session-tab${active}${selected}" type="button" draggable="true" data-session-key="${escapeHtml(key)}" title="${escapeHtml(session.cwd || session.display || key)}">
            <span class="session-tab-close" data-session-close="${escapeHtml(key)}" aria-label="Close tab" title="Close tab">x</span>
            <span class="session-tab-title">${escapeHtml(sessionTitle(session))}</span>
            <span class="session-tab-meta">${escapeHtml(sessionMeta(session))}</span>
          </button>
	        `;
	      }).join("") + launchTab;
	      if (!selectedControlSessionKey || document.getElementById("controlModal").hidden) {
	        resetMobileComposerFocus();
	        renderMobileControlStatus(null);
	      }
	      syncDiscussionPaneVisibility();
	      updateControlDockGeometry();
	    }

		    function orderedSessionKeysFromTabs() {
		      return Array.from(document.querySelectorAll("#sessionTabs .session-tab[data-session-key]"))
		        .map((tab) => tab.dataset.sessionKey || "")
		        .filter(Boolean);
		    }

		    function clearSessionTabDropClasses() {
		      document.querySelectorAll("#sessionTabs .session-tab").forEach((tab) => {
		        tab.classList.remove("dragging", "drop-before", "drop-after");
		      });
		    }

		    function sendSessionTabOrder() {
		      if (!socket || socket.readyState !== WebSocket.OPEN) return;
		      const sessionKeys = orderedSessionKeysFromTabs();
		      if (!sessionKeys.length) return;
		      socket.send(JSON.stringify({
		        action: "reorder_sessions",
		        session_keys: sessionKeys,
		      }));
		    }

		    function sessionTabDropPosition(tab, event) {
		      const rect = tab.getBoundingClientRect();
		      return event.clientX > rect.left + rect.width / 2 ? "after" : "before";
		    }

		    async function forgetControlSession(sessionKey) {
		      if (!sessionKey || !socket || socket.readyState !== WebSocket.OPEN) return;
		      const sessions = controlSessions({ control_plane: latestControlPlane });
		      const session = sessions.find((item) => item.key === sessionKey);
		      if (!session) return;
	      const live = sessionIsLive(session);
	      const provider = String(session.provider || "CLI").toUpperCase();
		      const label = String(session.cwd || session.display || sessionKey);
		      if (live) {
		        const first = await confirmAction({
		          title: "Forget live session",
	          message: `This session appears live. Forgetting it will close the associated ${provider} launcher and remove it from the dashboard:\n\n${label}`,
		          acceptLabel: "Continue",
		          danger: true
		        });
		        if (!first) return;
		        const second = await confirmAction({
		          title: "Close launcher",
		          message: `Confirm again: close this live launcher and forget the session?\n\n${label}`,
		          acceptLabel: "Close launcher",
		          danger: true
		        });
		        if (!second) return;
		      } else {
		        const confirmed = await confirmAction({
		          title: "Forget session",
		          message: `Forget this idle observed session from the dashboard?\n\n${label}`,
		          acceptLabel: "Forget",
		          danger: false
		        });
		        if (!confirmed) return;
		      }
		      socket.send(JSON.stringify({
		        action: "forget_session",
		        session_key: sessionKey,
		        force_live: live,
		      }));
		      if (selectedControlSessionKey === sessionKey) {
		        selectedControlSessionKey = "";
		        const modal = document.getElementById("controlModal");
		        if (modal) modal.hidden = true;
		      }
		    }

	    function launcherSessionScore(session) {
	      const key = String(session.key || "");
	      let score = 0;
	      if (key && key === selectedControlSessionKey) score += 16;
	      if (key && key === selectedLauncherSessionKey) score += 8;
	      if (!session.ui_launched) score += 4;
	      if (session.pty_control_available) score += 2;
	      if (session.active) score += 1;
	      return score;
	    }

		    function dedupedLauncherSessions(sessions) {
		      const byWorkdir = new Map();
	      for (const session of sessions) {
	        const key = String(session.key || "");
	        const cwd = String(session.cwd || session.display || key);
	        if (!key || !cwd) continue;
	        const workdirKey = cwd;
	        const existing = byWorkdir.get(workdirKey);
	        if (!existing || launcherSessionScore(session) > launcherSessionScore(existing)) {
	          byWorkdir.set(workdirKey, session);
	        }
	      }
		      return Array.from(byWorkdir.values());
		    }

		    function renderResumeCandidateOptions(candidates, selectedId) {
		      if (!candidates.length) return '<option value="">No resumable sessions found</option>';
		      return candidates.map((candidate) => {
		        const id = String(candidate.id || "");
		        const when = candidate.timestamp ? formatEventTime(candidate.timestamp) : "";
		        const label = `${when ? `${when} - ` : ""}${candidate.label || id}`;
		        return `<option value="${escapeHtml(id)}" ${id === selectedId ? "selected" : ""}>${escapeHtml(label)}</option>`;
		      }).join("");
		    }

		    function renderLauncherBar(status) {
		      const bar = document.getElementById("launcherBar");
		      const select = document.getElementById("launcherSession");
		      const modeSelect = document.getElementById("launcherMode");
		      const permissionSelect = document.getElementById("launcherPermission");
		      const resumeField = document.getElementById("launcherResumeField");
		      const resumeSelect = document.getElementById("launcherResumeSession");
		      const start = document.getElementById("launcherStart");
		      if (!bar || !select || !modeSelect || !permissionSelect || !resumeField || !resumeSelect || !start) return;
		      bar.hidden = !launcherPanelOpen;
		      if (!launcherPanelOpen) {
		        updateControlDockGeometry();
		        return;
	      }
	      const sessions = controlSessions(status);
	      const known = dedupedLauncherSessions(sessions.filter((session) => String(session.provider || "codex") === "codex"));
	      if (!selectedLauncherSessionKey && selectedControlSessionKey && known.some((session) => session.key === selectedControlSessionKey)) {
	        selectedLauncherSessionKey = selectedControlSessionKey;
	      }
	      if (!selectedLauncherSessionKey || !known.some((session) => session.key === selectedLauncherSessionKey)) {
	        selectedLauncherSessionKey = known.length ? String(known[0].key || "") : "";
	      }
	      select.innerHTML = known.length
	        ? known.map((session) => {
	          const key = String(session.key || "");
	          const label = `${session.cwd || session.display || key}${session.associated_profile ? ` (${session.associated_profile})` : ""}`;
	          return `<option value="${escapeHtml(key)}" ${key === selectedLauncherSessionKey ? "selected" : ""}>${escapeHtml(label)}</option>`;
	        }).join("")
		        : '<option value="">No observed workdirs</option>';
	      select.disabled = !known.length;
	      const selectedSession = known.find((session) => String(session.key || "") === selectedLauncherSessionKey) || null;
	      if (selectedSession) requestResumeCandidates(selectedSession);
	      const candidates = selectedSession ? resumeCandidatesForSession(selectedSession) : [];
		      if (!launcherResumeSessionId || !candidates.some((candidate) => String(candidate.id || "") === launcherResumeSessionId)) {
		        launcherResumeSessionId = candidates.length ? String(candidates[0].id || "") : "";
		      }
		      modeSelect.value = launcherMode;
		      permissionSelect.value = launcherPermission;
		      resumeField.hidden = launcherMode !== "resume-session";
		      resumeSelect.innerHTML = renderResumeCandidateOptions(candidates, launcherResumeSessionId);
		      resumeSelect.disabled = launcherMode !== "resume-session" || !candidates.length;
		      const needsResumeSelection = launcherMode === "resume-session";
		      start.disabled = !known.length
		        || !socket
		        || socket.readyState !== WebSocket.OPEN
		        || (needsResumeSelection && !launcherResumeSessionId);
		      updateControlDockGeometry();
		    }

	    function selectedControlSession() {
	      const sessions = controlSessions({ control_plane: latestControlPlane });
	      return sessions.find((session) => session.key === selectedControlSessionKey) || null;
	    }

	    function controlCapabilityText(session) {
	      const interaction = latestControlPlane && typeof latestControlPlane.interaction === "object"
	        ? latestControlPlane.interaction
	        : {};
	      const sessionInteraction = session && typeof session.interaction === "object"
	        ? session.interaction
	        : {};
	      if (sessionInteraction.reason) return String(sessionInteraction.reason);
	      const provider = String(session && session.provider || "supported CLI");
	      return String(interaction.reason || `Launch this ${provider} session with Provision to enable live UI input.`);
	    }

	    function controlInteractionAvailable(session) {
	      return Boolean(session && session.interaction && session.interaction.available);
	    }

	    function updateControlComposeState(session) {
	      const prompt = document.getElementById("controlPrompt");
	      const button = document.getElementById("controlSend");
	      const available = controlInteractionAvailable(session);
	      prompt.disabled = !available;
	      button.disabled = !available || !prompt.value.trim();
	      prompt.placeholder = available
	        ? `Send to running ${String(session && session.provider || "CLI").toUpperCase()}`
	        : controlCapabilityText(session);
	    }

		    function resetControlPromptHistory() {
		      controlPromptHistoryIndex = null;
		      controlPromptHistorySessionKey = "";
		      controlPromptHistoryDraft = "";
		    }

		    function controlPromptHistory(session) {
		      const transcript = session && Array.isArray(session.transcript) ? session.transcript : [];
		      const history = [];
		      let previous = "";
		      for (const item of transcript) {
		        if (String(item.role || "") !== "user") continue;
		        const text = String(item.full_text || item.text || "").trim();
		        if (!text || text === previous) continue;
		        previous = text;
		        history.push(text);
		      }
		      return history;
		    }

		    function setControlPromptValue(value) {
		      const prompt = document.getElementById("controlPrompt");
		      if (!prompt) return;
		      prompt.value = value;
		      updateControlComposeState(selectedControlSession());
		      requestAnimationFrame(() => {
		        const end = prompt.value.length;
		        try {
		          prompt.setSelectionRange(end, end);
		        } catch {
		        }
		      });
		    }

		    function handleControlPromptHistory(event) {
		      if (!["ArrowUp", "ArrowDown"].includes(event.key) || event.shiftKey || event.altKey || event.metaKey || event.ctrlKey) {
		        return false;
		      }
		      const prompt = event.currentTarget;
		      if (!(prompt instanceof HTMLTextAreaElement) || prompt.disabled) return false;
		      const browsing = controlPromptHistoryIndex !== null
		        && controlPromptHistorySessionKey === selectedControlSessionKey;
		      if (prompt.value.trim() && !browsing) return false;
		      const history = controlPromptHistory(selectedControlSession());
		      if (!history.length) return false;
		      event.preventDefault();
		      if (!browsing) {
		        controlPromptHistorySessionKey = selectedControlSessionKey;
		        controlPromptHistoryDraft = prompt.value;
		        controlPromptHistoryIndex = history.length;
		      }
		      if (event.key === "ArrowUp") {
		        controlPromptHistoryIndex = Math.max(0, Number(controlPromptHistoryIndex) - 1);
		        setControlPromptValue(history[controlPromptHistoryIndex] || "");
		        return true;
		      }
		      controlPromptHistoryIndex = Math.min(history.length, Number(controlPromptHistoryIndex) + 1);
		      if (controlPromptHistoryIndex >= history.length) {
		        const draft = controlPromptHistoryDraft;
		        resetControlPromptHistory();
		        setControlPromptValue(draft);
		        return true;
		      }
		      setControlPromptValue(history[controlPromptHistoryIndex] || "");
		      return true;
		    }

	    function renderControlActiveDetails(session) {
	      const details = session.active_details && typeof session.active_details === "object" ? session.active_details : {};
	      const requests = Array.isArray(details.requests) ? details.requests : [];
	      const tunnels = Array.isArray(details.tunnels) ? details.tunnels : [];
	      const requestCards = requests.map((request) => `
	        <div class="control-active-card">
	          <strong>Request</strong>
	          <span>Profile: ${escapeHtml(request.profile || "unknown")}</span>
	          ${request.age_seconds != null ? `<span>Age: ${escapeHtml(formatAge(request.age_seconds))}</span>` : ""}
	        </div>
	      `);
	      const tunnelCards = tunnels.map((tunnel, index) => {
	        const traffic = `${formatBytes(tunnel.bytes_up)} up / ${formatBytes(tunnel.bytes_down)} down`;
	        const messages = `${formatNumber(tunnel.messages_up)} up / ${formatNumber(tunnel.messages_down)} down`;
	        const bits = [];
	        const hasTurn = Number(tunnel.pending_work || 0) > 0 || Boolean(tunnel.turn_id);
	        const label = `${hasTurn ? "Turn tunnel" : "Session tunnel"} ${index + 1}`;
	        if (Number(tunnel.pending_work || 0) > 0) bits.push("active");
	        else bits.push("idle");
	        if (tunnel.service_tier) bits.push(String(tunnel.service_tier));
	        return `
	          <div class="control-active-card">
	            <strong>${escapeHtml(label)}${bits.length ? ` (${escapeHtml(bits.join(", "))})` : ""}</strong>
	            <span>Profile: ${escapeHtml(tunnel.profile || "unknown")}</span>
	            ${tunnel.turn_id ? `<span>Turn: ${escapeHtml(tunnel.turn_id)}</span>` : ""}
	            ${tunnel.age_seconds != null ? `<span>Open: ${escapeHtml(formatAge(tunnel.age_seconds))}</span>` : ""}
	            ${tunnel.last_data_age_seconds != null ? `<span>Last data: ${escapeHtml(formatAge(tunnel.last_data_age_seconds))} ago</span>` : ""}
	            <span>Traffic: ${escapeHtml(traffic)}</span>
	            <span>Messages: ${escapeHtml(messages)}</span>
	          </div>
	        `;
	      });
	      const cards = requestCards.concat(tunnelCards);
	      if (!cards.length) return '<div class="control-empty">No active request or tunnel is currently attached to this session</div>';
	      return `<div class="control-active-grid">${cards.join("")}</div>`;
	    }

	    function controlTranscriptMatches(item, query) {
	      if (!query) return true;
	      const haystack = `${item.role || ""} ${item.text || ""} ${item.full_text || ""} ${item.search_text || ""}`.toLowerCase();
	      return haystack.includes(query.toLowerCase());
	    }

	    function controlTurnKey(turn) {
	      return String(turn && (turn.key || turn.turn_id || turn.start_index) || "");
	    }

	    function historyCacheKey(sessionKey, turnKey) {
	      return `${sessionKey || ""}\u0001${turnKey || ""}`;
	    }

	    function historyTurnPayload(session, turn) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      const turnKey = controlTurnKey(turn);
	      return historyTurnCache[historyCacheKey(sessionKey, turnKey)] || null;
	    }

	    function observedTurnPayload(session, turn) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      const turnKey = controlTurnKey(turn);
	      return observedTurnCache[historyCacheKey(sessionKey, turnKey)] || null;
	    }

	    function controlTranscriptItemIdentity(item, fallbackIndex) {
	      const itemId = String(item && item.item_id || "");
	      if (itemId) return `item:${itemId}`;
	      const controlIndex = Number(item && item.control_index);
	      if (Number.isFinite(controlIndex)) return `index:${controlIndex}`;
	      return `fallback:${fallbackIndex}`;
	    }

	    function mergeControlTranscriptItems(olderItems, newerItems) {
	      const merged = new Map();
	      let fallbackIndex = 0;
	      for (const items of [olderItems, newerItems]) {
	        for (const item of Array.isArray(items) ? items : []) {
	          if (!item || typeof item !== "object") continue;
	          const key = controlTranscriptItemIdentity(item, fallbackIndex++);
	          const existing = merged.get(key);
	          merged.set(key, existing ? { ...existing, ...item } : item);
	        }
	      }
	      return Array.from(merged.values()).sort((left, right) => {
	        const leftIndex = Number(left && left.control_index);
	        const rightIndex = Number(right && right.control_index);
	        if (Number.isFinite(leftIndex) && Number.isFinite(rightIndex)) {
	          return leftIndex - rightIndex;
	        }
	        if (Number.isFinite(leftIndex)) return -1;
	        if (Number.isFinite(rightIndex)) return 1;
	        return 0;
	      });
	    }

	    function observedTurnPayloadEdge(payload, edge) {
	      const rows = payload && Array.isArray(payload.transcript) ? payload.transcript : [];
	      if (!rows.length) return NaN;
	      const row = edge === "last" ? rows[rows.length - 1] : rows[0];
	      return Number(row && row.control_index);
	    }

	    function mergeObservedTurnPayload(existing, incoming) {
	      if (!existing || !Array.isArray(existing.transcript)) {
	        return { ...incoming, transcript: Array.isArray(incoming.transcript) ? incoming.transcript.slice() : [] };
	      }
	      const existingFirst = observedTurnPayloadEdge(existing, "first");
	      const incomingFirst = observedTurnPayloadEdge(incoming, "first");
	      const earliest = !Number.isFinite(existingFirst)
	        || (Number.isFinite(incomingFirst) && incomingFirst <= existingFirst)
	        ? incoming
	        : existing;
	      return {
	        ...existing,
	        ...incoming,
	        transcript: mergeControlTranscriptItems(existing.transcript, incoming.transcript),
	        has_more_before: Boolean(earliest && earliest.has_more_before),
	        next_before_index: earliest && earliest.next_before_index != null
	          ? earliest.next_before_index
	          : null
	      };
	    }

	    function observedTurnNeedsLoad(session, turn) {
	      if (!turn || turn.source === "history" || observedTurnPayload(session, turn)) return false;
	      const window = session && session.transcript_window && typeof session.transcript_window === "object"
	        ? session.transcript_window
	        : null;
	      if (!window) return false;
	      const start = Number(window.start_index);
	      const end = Number(window.end_index);
	      const turnStart = Number(turn.start_index);
	      const turnEnd = Number(turn.end_index);
	      return Number.isFinite(start) && Number.isFinite(end)
	        && Number.isFinite(turnStart) && Number.isFinite(turnEnd)
	        && (turnStart < start || turnEnd > end);
	    }

	    function requestObservedTurn(session, turn, beforeIndex = null, refreshLatest = false) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      const turnKey = controlTurnKey(turn);
	      if (!sessionKey || !turnKey || !socket || socket.readyState !== WebSocket.OPEN) return false;
	      const latestVersion = Number(turn && turn.end_index);
	      const requestCursor = beforeIndex == null
	        ? `latest:${Number.isFinite(latestVersion) ? latestVersion : "current"}`
	        : beforeIndex;
	      const key = `${historyCacheKey(sessionKey, turnKey)}\u0001${requestCursor}`;
	      if (observedTurnRequests[key]) return false;
	      if (beforeIndex == null && observedTurnPayload(session, turn) && !refreshLatest) return false;
	      observedTurnRequests[key] = true;
	      socket.send(JSON.stringify({
	        action: "load_control_turn",
	        session_key: sessionKey,
	        turn_key: turnKey,
	        before_index: beforeIndex,
	      }));
	      return true;
	    }

	    function requestTerminalSnapshot(session) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      if (!sessionKey || !session || !session.pty_control_available || !socket || socket.readyState !== WebSocket.OPEN) return false;
	      const now = Date.now();
	      const last = Number(terminalSnapshotRequests[sessionKey] || 0);
	      if (last && now - last < 750) return false;
	      terminalSnapshotRequests[sessionKey] = now;
	      socket.send(JSON.stringify({
	        action: "terminal_snapshot",
	        session_key: sessionKey,
	      }));
	      return true;
	    }

	    function clearTerminalSnapshotRefresh() {
	      if (!terminalSnapshotRefreshTimer) return;
	      clearTimeout(terminalSnapshotRefreshTimer);
	      terminalSnapshotRefreshTimer = null;
	    }

	    function scheduleTerminalSnapshotRefresh() {
	      clearTerminalSnapshotRefresh();
	      if (controlView !== "terminal" || !selectedControlSessionKey) return;
	      terminalSnapshotRefreshTimer = setTimeout(() => {
	        terminalSnapshotRefreshTimer = null;
	        const session = selectedControlSession();
	        if (!session || controlView !== "terminal") return;
	        requestTerminalSnapshot(session);
	        scheduleTerminalSnapshotRefresh();
	      }, 1000);
	    }

	    function renderControlTerminal(session) {
	      if (!session || !session.pty_control_available) {
	        return '<div class="control-empty">A live terminal view is available only for a session launched through Provision\'s managed PTY.</div>';
	      }
	      const key = String(session.key || selectedControlSessionKey || "");
	      const snapshot = terminalSnapshotCache[key];
	      requestTerminalSnapshot(session);
	      scheduleTerminalSnapshotRefresh();
	      if (!snapshot) return '<div class="control-empty">Loading the bounded terminal tail…</div>';
	      const notice = snapshot.truncated
	        ? '<div class="control-terminal-note">Showing a bounded recent terminal tail. It is not retained in Discussion, search, or remote state.</div>'
	        : '<div class="control-terminal-note">Live local terminal tail. Terminal control sequences are rendered as plain text.</div>';
	      const text = String(snapshot.text || "");
	      return `${notice}<pre class="control-terminal" data-control-inner-scroll="terminal">${escapeHtml(text || "No terminal output captured yet.")}</pre>`;
	    }

	    function requestHistoryTurn(session, turn) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      const turnKey = controlTurnKey(turn);
	      if (!sessionKey || !turnKey || !socket || socket.readyState !== WebSocket.OPEN) return false;
	      const key = historyCacheKey(sessionKey, turnKey);
	      if (historyTurnCache[key] || historyTurnRequests[key]) return false;
	      historyTurnRequests[key] = true;
	      socket.send(JSON.stringify({
	        action: "load_history_turn",
	        session_key: sessionKey,
	        turn_key: turnKey,
	      }));
	      return true;
	    }

	    function historyTurnsForSession(session) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      if (Object.prototype.hasOwnProperty.call(historyTurnIndexes, sessionKey)) {
	        return historyTurnIndexes[sessionKey];
	      }
	      return session && Array.isArray(session.history_turns) ? session.history_turns : [];
	    }

	    function requestHistoryIndex(session) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      if (!sessionKey || !socket || socket.readyState !== WebSocket.OPEN) return false;
	      if (
	        Object.prototype.hasOwnProperty.call(historyTurnIndexes, sessionKey)
	        || historyIndexRequests[sessionKey]
	      ) return false;
	      historyIndexRequests[sessionKey] = true;
	      socket.send(JSON.stringify({
	        action: "load_history_index",
	        session_key: sessionKey,
	      }));
	      return true;
	    }

	    function resumeCandidatesForSession(session) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      if (Object.prototype.hasOwnProperty.call(resumeCandidateIndexes, sessionKey)) {
	        return resumeCandidateIndexes[sessionKey];
	      }
	      return session && Array.isArray(session.resume_candidates) ? session.resume_candidates : [];
	    }

	    function requestResumeCandidates(session) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      if (!sessionKey || !socket || socket.readyState !== WebSocket.OPEN) return false;
	      if (
	        Object.prototype.hasOwnProperty.call(resumeCandidateIndexes, sessionKey)
	        || resumeCandidateRequests[sessionKey]
	      ) return false;
	      resumeCandidateRequests[sessionKey] = true;
	      socket.send(JSON.stringify({
	        action: "load_resume_candidates",
	        session_key: sessionKey,
	      }));
	      return true;
	    }

	    function controlTurns(session, transcript = null) {
	      const liveTurns = session && Array.isArray(session.turns)
	        ? session.turns.map((turn) => ({ ...turn, source: turn.source || "live" }))
	        : [];
	      const historyTurns = historyTurnsForSession(session)
	        .map((turn) => ({ ...turn, source: "history" }))
	        .filter((historyTurn) => !liveTurns.some((liveTurn) => {
	          const historyId = String(historyTurn.turn_id || "");
	          const liveId = String(liveTurn.turn_id || "");
	          if (historyId && liveId && !historyId.startsWith("history:")) return historyId === liveId;
	          const historyLabel = String(historyTurn.label || "").trim().toLowerCase();
	          const liveLabel = String(liveTurn.label || "").trim().toLowerCase();
	          if (!historyLabel || historyLabel !== liveLabel) return false;
	          const historyTime = Date.parse(String(historyTurn.timestamp || ""));
	          const liveTime = Date.parse(String(liveTurn.timestamp || ""));
	          return Number.isFinite(historyTime) && Number.isFinite(liveTime)
	            && Math.abs(historyTime - liveTime) <= 15000;
	        }));
	      const turns = historyTurns.concat(liveTurns);
	      if (turns.length) return turns;
	      const rows = transcript || (session && Array.isArray(session.transcript) ? session.transcript : []);
	      if (!rows.length) return [];
	      return [{
	        key: "observed-activity",
	        source: "live",
	        label: "Observed activity",
	        start_index: 0,
	        end_index: rows.length - 1,
	        timestamp: rows[0].ts || "",
	        updated_at: rows[rows.length - 1].updated_at || rows[rows.length - 1].ts || ""
	      }];
	    }

	    function transcriptItemsForTurn(transcript, turn) {
	      if (turn && turn.source === "history") return [];
	      const start = Math.max(0, Number(turn && turn.start_index || 0));
	      const end = Math.max(start, Number(turn && turn.end_index != null ? turn.end_index : start));
	      return transcript.filter((item) => {
	        const index = Number(item.control_index);
	        return Number.isFinite(index) && index >= start && index <= end;
	      });
	    }

	    function turnTranscriptItems(session, transcript, turn) {
	      if (turn && turn.source === "history") {
	        const payload = historyTurnPayload(session, turn);
	        return payload && Array.isArray(payload.transcript) ? payload.transcript : [];
	      }
	      const live = transcriptItemsForTurn(transcript, turn);
	      const observed = observedTurnPayload(session, turn);
	      if (!observed || !Array.isArray(observed.transcript)) return live;
	      const merged = mergeControlTranscriptItems(observed.transcript, live);
	      observed.transcript = merged;
	      return merged;
	    }

	    function observedTurnHasLiveGap(session, transcript, turn) {
	      const observed = observedTurnPayload(session, turn);
	      if (!observed || !Array.isArray(observed.transcript)) return false;
	      const live = transcriptItemsForTurn(transcript, turn);
	      if (!live.length) return false;
	      const cachedLast = observedTurnPayloadEdge(observed, "last");
	      const liveFirst = Number(live[0] && live[0].control_index);
	      return Number.isFinite(cachedLast)
	        && Number.isFinite(liveFirst)
	        && liveFirst > cachedLast + 1;
	    }

	    function turnMatchesSearch(transcript, turn, query, session = null) {
	      if (!query) return true;
	      const label = String(turn && turn.label || "").toLowerCase();
	      const needle = query.toLowerCase();
	      if (label.includes(needle)) return true;
	      const searchText = String(turn && turn.search_text || "").toLowerCase();
	      if (searchText.includes(needle)) return true;
	      return turnTranscriptItems(session, transcript, turn).some((item) => controlTranscriptMatches(item, query));
	    }

	    function turnOptionLabel(turn, transcript, query, session = null) {
	      const when = turn && turn.timestamp ? formatEventTime(turn.timestamp) : "";
	      const label = String(turn && turn.label || turn && turn.turn_id || "Observed turn");
	      let prefix = when ? `${when} - ` : "";
	      let suffix = turn && turn.pending ? " (pending)" : "";
	      if (turn && turn.source === "history") suffix += turn.archived ? " (archived)" : " (history)";
	      if (query) {
	        const matches = turnTranscriptItems(session, transcript, turn)
	          .filter((item) => controlTranscriptMatches(item, query)).length;
	        if (matches > 0) suffix += ` (${matches} loaded match${matches === 1 ? "" : "es"})`;
	        else if (String(turn && turn.search_text || "").toLowerCase().includes(query.toLowerCase())) suffix += " (match)";
	      }
	      return `${prefix}${label}${suffix}`;
	    }

	    function mobileLayoutActive() {
	      return window.matchMedia("(max-width: 860px)").matches;
	    }

	    function discussionActive() {
	      const modal = document.getElementById("controlModal");
	      return Boolean(
	        controlView === "discussion"
	        && selectedControlSessionKey
	        && modal
	        && !modal.hidden
	      );
	    }

	    function syncDiscussionPaneVisibility() {
	      const profiles = document.getElementById("profilesPanel");
	      const active = discussionActive();
	      document.body.classList.toggle("discussion-active", active);
	      if (profiles) profiles.hidden = active;
	    }

	    function updateMobileControlChromeGeometry() {
	      const root = document.documentElement;
	      const tabs = document.getElementById("sessionTabs");
	      const status = document.getElementById("mobileControlStatus");
	      if (!root || !tabs) return;
	      const visualViewport = window.visualViewport;
	      const viewportHeight = visualViewport && Number.isFinite(visualViewport.height)
	        ? visualViewport.height
	        : window.innerHeight;
	      const focused = (mobileDiscussionFocused || mobileComposerFocused) && mobileLayoutActive();
	      const viewportTop = visualViewport && Number.isFinite(visualViewport.offsetTop)
	        ? Math.max(0, Math.round(visualViewport.offsetTop))
	        : 0;
	      const tabsHeight = focused ? 0 : tabs.offsetHeight;
	      const statusHeight = focused || !status || status.hidden ? 0 : status.offsetHeight;
	      const dockHeight = Math.max(0, Math.round(viewportHeight) - tabsHeight - statusHeight);
	      root.style.setProperty("--mobile-viewport-height", `${Math.max(0, Math.round(viewportHeight))}px`);
	      root.style.setProperty("--mobile-visual-viewport-top", `${viewportTop}px`);
	      root.style.setProperty("--mobile-session-tabs-height", `${tabsHeight}px`);
	      root.style.setProperty("--mobile-control-chrome-height", `${tabsHeight + statusHeight}px`);
	      root.style.setProperty("--mobile-control-dock-height", `${dockHeight}px`);
	    }

	    function renderMobileControlStatus(session) {
	      const status = document.getElementById("mobileControlStatus");
	      const readouts = document.getElementById("mobileControlReadouts");
	      const focus = document.getElementById("mobileFocusToggle");
	      if (!status || !readouts || !focus) return;
	      if (!session) {
	        status.hidden = true;
	        updateMobileControlChromeGeometry();
	        return;
	      }
	      const pills = [];
	      if (session.context && session.context.label) {
	        const contextTitle = [
	          session.context.input_tokens ? `${formatNumber(session.context.input_tokens)} input tokens` : "",
	          session.context.remaining_tokens ? `${formatNumber(session.context.remaining_tokens)} tokens remaining` : "",
	          session.context.updated_at ? `Updated ${formatEventTime(session.context.updated_at)}` : ""
	        ].filter(Boolean).join(" / ");
	        pills.push(`<span class="pill" title="${escapeHtml(contextTitle)}">Context <strong>${escapeHtml(session.context.label)}</strong></span>`);
	      } else {
	        pills.push('<span class="pill">Context <strong>unavailable</strong></span>');
	      }
	      if (session.quota_compact_html) pills.push(String(session.quota_compact_html));
	      readouts.innerHTML = pills.join("");
	      status.hidden = false;
	      focus.hidden = controlView !== "discussion";
	      focus.setAttribute("aria-pressed", mobileDiscussionFocused ? "true" : "false");
	      focus.textContent = mobileDiscussionFocused ? "Show controls" : "Focus discussion";
	      updateMobileControlChromeGeometry();
	      requestAnimationFrame(updateMobileControlStickiness);
	    }

	    function resetMobileControlStickiness() {
	      mobileControlDockAnchorY = null;
	      document.body.classList.remove("mobile-control-stuck");
	    }

	    function updateMobileControlStickiness() {
	      const modal = document.getElementById("controlModal");
	      const status = document.getElementById("mobileControlStatus");
	      if (
	        !mobileLayoutActive()
	        || !selectedControlSessionKey
	        || !modal
	        || modal.hidden
	      ) {
	        resetMobileControlStickiness();
	        return;
	      }
	      if (mobileControlDockAnchorY == null) {
	        if (!mobileDiscussionFocused && !mobileComposerFocused && status && status.hidden) return;
	        const chrome = Number.parseFloat(
	          getComputedStyle(document.documentElement).getPropertyValue("--mobile-control-chrome-height")
	        ) || 0;
	        const bounds = modal.getBoundingClientRect();
	        mobileControlDockAnchorY = Math.max(0, bounds.top + window.scrollY - chrome);
	      }
	      const shouldStick = mobileDiscussionFocused || mobileComposerFocused || window.scrollY >= mobileControlDockAnchorY - 1;
	      document.body.classList.toggle("mobile-control-stuck", shouldStick);
	    }

	    function documentAtBottom() {
	      const root = document.documentElement;
	      const visualViewport = window.visualViewport;
	      const viewportHeight = visualViewport && Number.isFinite(visualViewport.height)
	        ? visualViewport.height
	        : window.innerHeight;
	      const documentHeight = Math.max(root.scrollHeight, document.body ? document.body.scrollHeight : 0);
	      return window.scrollY + viewportHeight >= documentHeight - 3;
	    }

	    function mobileGestureTargetsDiscussion(target) {
	      return target instanceof Element && Boolean(target.closest("#controlContent, #controlCompose, [data-control-inner-scroll]"));
	    }

	    function setMobileDiscussionFocus(focused) {
	      if (!mobileLayoutActive() || controlView !== "discussion" || !selectedControlSessionKey) return false;
	      if (focused) resetMobileComposerFocus();
	      mobileDiscussionFocused = Boolean(focused);
	      document.body.classList.toggle("mobile-discussion-focus", mobileDiscussionFocused);
	      const restore = document.getElementById("mobileFocusRestore");
	      if (restore) restore.hidden = !mobileDiscussionFocused;
	      renderMobileControlStatus(selectedControlSession());
	      requestAnimationFrame(() => {
	        updateMobileControlChromeGeometry();
	        if (mobileDiscussionFocused) window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "auto" });
	      });
	      return true;
	    }

	    function resetMobileDiscussionFocus() {
	      mobileDiscussionFocused = false;
	      document.body.classList.remove("mobile-discussion-focus");
	      const restore = document.getElementById("mobileFocusRestore");
	      if (restore) restore.hidden = true;
	      updateMobileControlChromeGeometry();
	    }

	    function setMobileComposerFocus(focused) {
	      if (!focused) {
	        resetMobileComposerFocus();
	        return false;
	      }
	      if (!mobileLayoutActive() || controlView !== "discussion" || !selectedControlSessionKey) return false;
	      mobileComposerFocused = true;
	      document.body.classList.add("mobile-composer-focus");
	      mobileControlDockAnchorY = null;
	      updateMobileControlChromeGeometry();
	      requestAnimationFrame(updateMobileControlStickiness);
	      return true;
	    }

	    function resetMobileComposerFocus() {
	      mobileComposerFocused = false;
	      document.body.classList.remove("mobile-composer-focus");
	      mobileControlDockAnchorY = null;
	      document.body.classList.remove("mobile-control-stuck");
	      updateMobileControlChromeGeometry();
	      requestAnimationFrame(updateMobileControlStickiness);
	    }

	    function handleMobileBoundaryGesture(deltaY, event) {
	      if (
	        !mobileLayoutActive()
	        || !selectedControlSessionKey
	        || controlView !== "discussion"
	        || Math.abs(deltaY) < MOBILE_FOCUS_GESTURE_DELTA
	        || mobileGestureTargetsDiscussion(event.target)
	        || !documentAtBottom()
	      ) return;
	      if (Date.now() < mobileFocusScrollLockUntil) {
	        if (event.cancelable) event.preventDefault();
	        return;
	      }
	      if (deltaY > 0 && !mobileDiscussionFocused) {
	        if (event.cancelable) event.preventDefault();
	        setMobileDiscussionFocus(true);
	      } else if (deltaY < 0 && mobileDiscussionFocused) {
	        if (event.cancelable) event.preventDefault();
	        setMobileDiscussionFocus(false);
	        mobileFocusScrollLockUntil = Date.now() + MOBILE_FOCUS_SCROLL_LOCK_MS;
	      }
	    }

	    function selectedTurnForSession(session, transcript) {
	      const turns = controlTurns(session, transcript);
	      if (!turns.length) return null;
	      const query = controlSearchText.trim();
	      const matchingTurns = query ? turns.filter((turn) => turnMatchesSearch(transcript, turn, query, session)) : turns;
	      const available = matchingTurns.length ? matchingTurns : turns;
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      const selectedKey = selectedControlTurnKeys[sessionKey] || "";
	      const selected = available.find((turn) => controlTurnKey(turn) === selectedKey);
	      const fallback = available[available.length - 1] || null;
	      if (fallback) selectedControlTurnKeys[sessionKey] = controlTurnKey(selected || fallback);
	      return selected || fallback;
	    }

	    function controlTurnPresentationKey(session) {
	      return `${String(session && session.key || selectedControlSessionKey || "none")}:${controlSearchText || ""}`;
	    }

	    function controlTurnByKey(turns, key) {
	      return turns.find((turn) => controlTurnKey(turn) === key) || null;
	    }

	    function controlTurnPresentation(session, transcript, selected) {
	      const sessionKey = String(session && session.key || selectedControlSessionKey || "");
	      const key = controlTurnPresentationKey(session);
	      if (
	        !sessionKey
	        || controlSearchText.trim()
	        || manuallySelectedControlTurnKeys[sessionKey]
	        || !selected
	        || selected.source === "history"
	      ) {
	        delete controlTurnPresentations[key];
	        return null;
	      }
	      const turns = controlTurns(session, transcript).filter((turn) => turn.source !== "history");
	      const latest = turns[turns.length - 1] || null;
	      if (!latest) return null;
	      const selectedKey = controlTurnKey(selected);
	      const state = controlTurnPresentations[key] || {
	        activeKey: selectedKey,
	        pendingKey: "",
	        hiddenKey: "",
	        revealedKey: ""
	      };
	      if (!controlTurnByKey(turns, state.activeKey)) state.activeKey = selectedKey;
	      if (controlTurnKey(latest) !== state.activeKey) state.pendingKey = controlTurnKey(latest);
	      if (state.pendingKey && !controlTurnByKey(turns, state.pendingKey)) state.pendingKey = "";
	      controlTurnPresentations[key] = state;
	      return { state, turns, active: controlTurnByKey(turns, state.activeKey) || selected, pending: controlTurnByKey(turns, state.pendingKey) };
	    }

	    function finalizeControlTurnBridgeIfScrolledAway() {
	      const content = document.getElementById("controlContent");
	      const session = selectedControlSession();
	      if (!content || !session || controlView !== "discussion") return;
	      const presentation = controlTurnPresentations[controlTurnPresentationKey(session)];
	      const boundary = content.querySelector("[data-control-turn-boundary]");
	      if (!presentation || (!presentation.pendingKey && !presentation.revealedKey) || !boundary) return;
	      const contentBounds = content.getBoundingClientRect();
	      if (boundary.getBoundingClientRect().bottom >= contentBounds.top + 4) return;
	      if (presentation.pendingKey) {
	        const turns = controlTurns(session, Array.isArray(session.transcript) ? session.transcript : [])
	          .filter((turn) => turn.source !== "history");
	        const activeIndex = turns.findIndex((turn) => controlTurnKey(turn) === presentation.activeKey);
	        const pendingIndex = turns.findIndex((turn) => controlTurnKey(turn) === presentation.pendingKey);
	        const next = activeIndex >= 0 && pendingIndex > activeIndex ? turns[activeIndex + 1] : null;
	        presentation.hiddenKey = presentation.activeKey;
	        presentation.activeKey = next ? controlTurnKey(next) : presentation.pendingKey;
	        if (presentation.activeKey === presentation.pendingKey) presentation.pendingKey = "";
	        selectedControlTurnKeys[String(session.key || selectedControlSessionKey || "")] = presentation.activeKey;
	      }
	      presentation.revealedKey = "";
	      controlScrollPositions[controlScrollKey()] = content.scrollTop;
	      preserveControlScrollOnNextRender = true;
	      renderControlModal(true);
	    }

	    function renderControlTurnOptions(session) {
	      const transcript = session && Array.isArray(session.transcript) ? session.transcript : [];
	      const turns = controlTurns(session, transcript);
	      if (!turns.length) return '<option value="">No observed turns</option>';
	      const selected = selectedTurnForSession(session, transcript);
	      const selectedKey = controlTurnKey(selected);
	      return turns.map((turn) => {
	        const key = controlTurnKey(turn);
	        const disabled = controlSearchText && !turnMatchesSearch(transcript, turn, controlSearchText, session) ? "disabled" : "";
	        return `<option value="${escapeHtml(key)}" ${key === selectedKey ? "selected" : ""} ${disabled}>${escapeHtml(turnOptionLabel(turn, transcript, controlSearchText, session))}</option>`;
	      }).join("");
	    }

	    function controlMessageKey(item, fallback) {
	      const parts = [
	        selectedControlSessionKey || "session",
	        item.role || "message",
	        item.turn_id || "",
	        item.call_id || "",
	        item.ts || ""
	      ];
	      if (item.ts || item.call_id || item.turn_id) return parts.join("|");
	      parts.push(fallback || "");
	      return parts.join("|");
	    }

	    function compactControlMessageNeedsExpansion(value) {
	      const text = String(value || "");
	      if (!text) return false;
	      return text.split("\n").length > 4 || text.length > 360;
	    }

		    function splitToolStatusSuffix(value) {
		      const match = String(value || "").match(/^(.*?)(?:\s+\(([^)]*)\))?$/);
		      const label = match ? match[1].trim() : String(value || "").trim();
		      const attrs = {};
		      const suffix = match && match[2] ? match[2] : "";
		      for (const part of suffix.split(/\s*,\s*/)) {
		        const status = part.match(/^status\s+(.+)$/i);
		        const exit = part.match(/^exit\s+(.+)$/i);
		        const duration = part.match(/^duration\s+(.+)$/i);
		        if (status) attrs.status = status[1].trim();
		        else if (exit) attrs.exit = exit[1].trim();
		        else if (duration) attrs.duration = duration[1].trim();
		      }
		      return { label, attrs };
		    }

		    function parseToolActivityText(value) {
		      const lines = String(value || "").replace(/\r\n?/g, "\n").split("\n");
		      const first = lines[0] || "";
		      const firstMatch = first.match(/^(Tool|Command):\s*(.+)$/i);
		      if (!firstMatch) return null;
		      const parsedFirst = splitToolStatusSuffix(firstMatch[2]);
		      const result = {
		        kind: firstMatch[1].toLowerCase(),
		        name: firstMatch[1].toLowerCase() === "tool" ? parsedFirst.label : "command",
		        command: firstMatch[1].toLowerCase() === "command" ? parsedFirst.label : "",
		        status: parsedFirst.attrs.status || "",
		        exit: parsedFirst.attrs.exit || "",
		        duration: parsedFirst.attrs.duration || "",
		        sections: []
		      };
		      const sectionLabels = new Set([
		        "agent path", "agent states", "agent thread", "arguments", "caller", "code",
		        "content", "details", "error", "fingerprint", "fragments", "input", "message",
		        "model", "output", "parameters", "patch", "prompt", "query", "reasoning",
		        "receiver agents", "receiver threads", "result", "results", "source", "status",
		        "stderr", "stdout", "summary"
		      ]);
		      const seenSectionLabels = new Set();
		      let currentSection = null;
		      const pushSection = () => {
		        if (!currentSection) return;
		        const text = currentSection.lines.join("\n").replace(/\s+$/g, "");
		        if (text.trim()) result.sections.push({ label: currentSection.label, text });
		        currentSection = null;
		      };
		      for (const rawLine of lines.slice(1)) {
		        const line = rawLine || "";
		        const commandMatch = line.match(/^Command:\s*(.+)$/i);
		        if (commandMatch) {
		          pushSection();
		          const parsedCommand = splitToolStatusSuffix(commandMatch[1]);
		          result.command = parsedCommand.label || result.command;
		          if (parsedCommand.attrs.status) result.status = parsedCommand.attrs.status;
		          if (parsedCommand.attrs.exit) result.exit = parsedCommand.attrs.exit;
		          if (parsedCommand.attrs.duration) result.duration = parsedCommand.attrs.duration;
		          continue;
		        }
		        const sectionMatch = line.match(/^([A-Za-z][A-Za-z0-9 _/-]{1,40}):\s*$/);
		        const sectionLabel = sectionMatch ? sectionMatch[1].trim() : "";
		        const sectionKey = sectionLabel.toLowerCase();
		        if (sectionLabels.has(sectionKey) && !seenSectionLabels.has(sectionKey)) {
		          pushSection();
		          currentSection = { label: sectionLabel, lines: [] };
		          seenSectionLabels.add(sectionKey);
		          continue;
		        }
		        if (!currentSection) currentSection = { label: "Details", lines: [] };
		        currentSection.lines.push(line);
		      }
		      pushSection();
		      return result;
		    }

		    function isControlToolName(name) {
		      return /^ctc_[a-f0-9]{16,}$/i.test(String(name || "").trim());
		    }

		    function toolSectionIsPatch(section) {
		      const label = String(section && section.label || "").toLowerCase();
		      const text = String(section && section.text || "");
		      return ["arguments", "input", "patch", "content"].includes(label) && /^\*\*\* Begin Patch/m.test(text);
		    }

		    function renderPatchText(text) {
			      return String(text || "").split("\n").map((line) => {
			        let cls = "context";
		        if (/^\*\*\* (Begin Patch|End Patch|Update File:|Add File:|Delete File:|Move to:)/.test(line) || /^@@/.test(line)) {
		          cls = "meta";
		        } else if (/^\+/.test(line)) {
		          cls = "add";
		        } else if (/^-/.test(line)) {
		          cls = "delete";
		        }
		        return `<span class="tool-patch-line ${cls}">${escapeHtml(line || " ")}</span>`;
			      }).join("");
			    }

			    function parseToolJsonText(value) {
			      const text = String(value || "").trim();
			      if (!text) return null;
			      if (/^[{[]/.test(text)) {
			        try {
			          return JSON.parse(text);
			        } catch {
			          return null;
			        }
			      }
			      const lines = text.split("\n");
			      const simple = {};
			      for (const line of lines) {
			        const match = line.match(/^([A-Za-z_][A-Za-z0-9_.-]*):\s*(.*)$/);
			        if (!match) return null;
			        simple[match[1]] = match[2];
			      }
			      return Object.keys(simple).length ? simple : null;
			    }

			    function toolSectionByLabel(parsed, labels) {
			      const wanted = new Set(labels.map((label) => label.toLowerCase()));
			      return (parsed.sections || []).find((section) => wanted.has(String(section.label || "").toLowerCase())) || null;
			    }

			    function toolPayloadFromLabels(parsed, labels) {
			      const section = toolSectionByLabel(parsed, labels);
			      return section ? parseToolJsonText(section.text) : null;
			    }

		    function toolSectionIsCollapsible(section) {
		      const label = String(section && section.label || "").toLowerCase();
		      const text = String(section && section.text || "");
		      return [
		        "arguments", "input", "parameters", "params", "content", "patch",
		        "output", "result", "results", "stdout", "stderr", "error"
		      ].includes(label)
		        && (text.includes("\n") || text.length > 180);
		    }

		    function summarizeToolSection(section, parsed) {
			      const text = String(section && section.text || "");
			      const payload = parseToolJsonText(text);
			      const name = String(parsed && parsed.name || "").toLowerCase();
		      const planItems = payload && name === "todo_write" && Array.isArray(payload.todos)
		        ? payload.todos
		        : (payload && name === "update_plan" && Array.isArray(payload.plan) ? payload.plan : null);
		      if (planItems) {
		        return `${planItems.length} plan step${planItems.length === 1 ? "" : "s"}`;
			      }
			      if (payload && name === "create_goal" && payload.objective) {
			        return `objective: ${payload.objective}`;
			      }
			      if (payload && name === "update_goal" && payload.status) {
			        return `status: ${payload.status}`;
			      }
			      if (payload && typeof payload.cmd === "string" && payload.cmd.trim()) return payload.cmd.trim();
			      if (payload && typeof payload.command === "string" && payload.command.trim()) return payload.command.trim();
			      const first = text.split("\n").map((line) => line.trim()).find(Boolean) || "";
		      return first.length > 220 ? `${first.slice(0, 220).trim()}...` : first;
		    }

		    function patchSummary(text) {
		      const files = [];
		      let added = 0;
		      let deleted = 0;
		      for (const line of String(text || "").split("\n")) {
		        const file = line.match(/^\*\*\* (Update|Add|Delete) File:\s*(.+)$/);
		        if (file) {
		          files.push({ operation: file[1].toLowerCase(), path: file[2].trim() });
		          continue;
		        }
		        const moved = line.match(/^\*\*\* Move to:\s*(.+)$/);
		        if (moved && files.length) files[files.length - 1].movedTo = moved[1].trim();
		        if (/^\+(?!\+\+)/.test(line)) added += 1;
		        if (/^-(?!---)/.test(line)) deleted += 1;
		      }
		      return { files, added, deleted };
		    }

		    function patchPreviewText(text, maxLines = 12) {
		      const lines = String(text || "").split("\n");
		      if (lines.length <= maxLines) return String(text || "");
		      const preview = lines.slice(0, maxLines);
		      preview.push("… patch preview truncated …");
		      return preview.join("\n");
		    }

		    function renderPatchToolSummary(parsed) {
		      const section = (parsed.sections || []).find((candidate) => toolSectionIsPatch(candidate));
		      if (!section) return "";
		      const source = toolSectionByLabel(parsed, ["Source"]);
		      const summary = patchSummary(section.text);
		      const fileBits = summary.files.slice(0, 2).map((file) => {
		        const target = file.movedTo ? ` → ${file.movedTo}` : "";
		        return `<span class="control-tool-patch-file">${escapeHtml(file.operation)} ${escapeHtml(file.path)}${escapeHtml(target)}</span>`;
		      });
		      if (summary.files.length > 2) fileBits.push(`<span>+${summary.files.length - 2} files</span>`);
		      const changes = [
		        summary.added ? `+${summary.added}` : "",
		        summary.deleted ? `-${summary.deleted}` : ""
		      ].filter(Boolean);
		      return `
		        <div class="control-tool-patch-summary">
		          ${source ? `<span>via ${escapeHtml(source.text)}</span>` : ""}
		          ${fileBits.join("")}
		          ${changes.length ? `<span>${escapeHtml(changes.join(" / "))} lines</span>` : ""}
		        </div>
		      `;
		    }

		    function toolSectionNeedsExpansion(section, parsed) {
		      if (!toolSectionIsCollapsible(section)) return false;
		      return summarizeToolSection(section, parsed) !== String(section && section.text || "");
		    }

			    function renderPlanToolSummary(parsed) {
			      const name = String(parsed.name || "").toLowerCase();
			      const args = toolPayloadFromLabels(parsed, ["Arguments", "Input", "Parameters"]);
			      const result = toolPayloadFromLabels(parsed, ["Result", "Output"]);
		      const planItems = name === "todo_write" && args && Array.isArray(args.todos)
		        ? args.todos.map((item) => ({ step: item.content || item.step, status: item.status }))
		        : (name === "update_plan" && args && Array.isArray(args.plan) ? args.plan : null);
		      if (planItems) {
		        const explanation = args.explanation
			          ? `<div class="control-tool-special-note">${escapeHtml(args.explanation)}</div>`
			          : "";
		        const rows = planItems.map((item) => {
			          const status = String(item && item.status || "pending");
			          const statusClass = status.toLowerCase().replace(/[^a-z0-9_-]+/g, "_");
			          const label = status.replace(/_/g, " ");
			          return `
			            <div class="control-tool-plan-row">
			              <span class="control-tool-plan-status ${escapeHtml(statusClass)}">${escapeHtml(label)}</span>
			              <span>${escapeHtml(item && item.step || "")}</span>
			            </div>
			          `;
			        }).join("");
			        return `
			          <div class="control-tool-special">
			            <div class="control-tool-special-title">
			              <span>Updated plan</span>
		              <span>${escapeHtml(planItems.length)} step${planItems.length === 1 ? "" : "s"}</span>
			            </div>
			            ${explanation}
			            <div class="control-tool-plan-list">${rows}</div>
			          </div>
			        `;
			      }
			      if (name === "create_goal" && args && args.objective) {
			        const budget = args.token_budget || args.tokenBudget
			          ? `<div class="control-tool-special-note">Budget: ${escapeHtml(args.token_budget || args.tokenBudget)} tokens</div>`
			          : "";
			        return `
			          <div class="control-tool-special">
			            <div class="control-tool-special-title"><span>Created goal</span></div>
			            <div>${escapeHtml(args.objective)}</div>
			            ${budget}
			          </div>
			        `;
			      }
			      if (name === "update_goal" && args && args.status) {
			        const goal = result && result.goal && typeof result.goal === "object" ? result.goal : null;
			        const usage = goal
			          ? [
			              goal.tokensUsed != null ? `Tokens: ${formatNumber(goal.tokensUsed)}` : "",
			              goal.timeUsedSeconds != null ? `Time: ${formatAge(goal.timeUsedSeconds)}` : ""
			            ].filter(Boolean).join(" / ")
			          : "";
			        return `
			          <div class="control-tool-special">
			            <div class="control-tool-special-title">
			              <span>Goal status</span>
			              <span>${escapeHtml(String(args.status))}</span>
			            </div>
			            ${goal && goal.objective ? `<div>${escapeHtml(goal.objective)}</div>` : ""}
			            ${usage ? `<div class="control-tool-special-note">${escapeHtml(usage)}</div>` : ""}
			          </div>
			        `;
			      }
			      if (name === "get_goal" && result && result.goal) {
			        const goal = result.goal;
			        return `
			          <div class="control-tool-special">
			            <div class="control-tool-special-title">
			              <span>Current goal</span>
			              <span>${escapeHtml(goal.status || "active")}</span>
			            </div>
			            ${goal.objective ? `<div>${escapeHtml(goal.objective)}</div>` : ""}
			          </div>
			        `;
			      }
			      return "";
			    }

		    function renderToolSection(section, ownerKey, sectionIndex, expanded, parsed) {
		      const isPatch = toolSectionIsPatch(section);
		      const collapsed = toolSectionNeedsExpansion(section, parsed) && !expanded;
		      const displayText = isPatch && collapsed
		        ? patchPreviewText(section.text)
		        : (collapsed ? summarizeToolSection(section, parsed) : section.text);
		      const body = isPatch ? renderPatchText(displayText) : escapeHtml(displayText);
		      const scrollKey = `${ownerKey}:section:${sectionIndex}:${section.label}`;
		      return `
		        <div class="control-tool-section${isPatch ? " patch" : ""}${collapsed ? " collapsed" : ""}">
		          <span class="control-tool-section-label">${escapeHtml(isPatch && collapsed ? "Patch preview" : section.label)}</span>
		          <pre data-control-inner-scroll="${escapeHtml(scrollKey)}">${body}</pre>
		        </div>
		      `;
		    }

	    function renderControlToolBlock(item, fallback, options = {}) {
	      const key = controlMessageKey(item, fallback);
	      const displayText = String(item.text || "");
	      const fullText = String(item.full_text || "");
	      const compact = Boolean(options.compact);
	      if (isContextCompactionPacket(item)) {
	        return `<div class="control-tool-block control-compaction-packet">${renderControlMessageText(item, fallback, { markdown: false, compact: true, compactionPacket: true })}</div>`;
	      }
	      const hasMore = Boolean(item.truncated || (fullText && fullText !== displayText));
		      const expanded = Boolean(expandedControlMessages[key]);
		      const text = expanded && fullText ? fullText : displayText;
		      const parsed = parseToolActivityText(text);
		      if (!parsed) {
		        return `<div class="control-tool-block"><strong>Tool / command</strong>${renderControlMessageText(item, fallback, { markdown: false, compact })}</div>`;
		      }
		      if (parsed.kind === "tool" && isControlToolName(parsed.name) && !parsed.command && !parsed.sections.length) {
		        return `
		          <div class="control-tool-block control-signal">
		            <div class="control-tool-summary">
		              <span class="control-tool-title">Control signal <code>${escapeHtml(parsed.name)}</code></span>
		              <span class="control-tool-status observed">observed</span>
		            </div>
		          </div>
		        `;
		      }
		      const status = String(item.status || parsed.status || "observed");
		      const statusClass = status.toLowerCase().replace(/[^a-z0-9_-]+/g, "_");
		      const summaryBits = [parsed.exit ? `exit ${parsed.exit}` : "", parsed.duration || ""].filter(Boolean);
			      const summary = summaryBits.length ? `<span>${escapeHtml(summaryBits.join(" / "))}</span>` : "";
		      const special = renderPlanToolSummary(parsed) + renderPatchToolSummary(parsed);
			      const command = parsed.command
			        ? `<div class="control-tool-command">${escapeHtml(parsed.command)}</div>`
			        : "";
		      const hasCollapsedSections = parsed.sections.some((section) => toolSectionNeedsExpansion(section, parsed));
			      const sections = parsed.sections.length
			        ? `<div class="control-tool-sections">${parsed.sections.map((section, sectionIndex) => renderToolSection(section, key, sectionIndex, expanded, parsed)).join("")}</div>`
			        : "";
		      const hasPatch = parsed.sections.some((section) => toolSectionIsPatch(section));
		      const button = hasMore || hasCollapsedSections
		        ? `<button class="control-show-more" type="button" data-message-key="${escapeHtml(key)}">${expanded ? "Show less" : (hasPatch ? "Show full patch" : "Show more")}</button>`
			        : "";
		      return `
		        <div class="control-tool-block">
		          <div class="control-tool-summary">
		            <span class="control-tool-title">${escapeHtml(parsed.kind === "command" ? "Command" : "Tool")} <code>${escapeHtml(parsed.name || parsed.command || "tool")}</code></span>
		            <span class="control-tool-status ${escapeHtml(statusClass)}">${escapeHtml(status)}</span>
			          </div>
			          ${summary}
			          ${special}
			          ${command}
			          ${sections}
			          ${button}
		        </div>
		      `;
		    }

	    function renderControlMessageText(item, fallback, options = {}) {
	      const key = controlMessageKey(item, fallback);
	      const role = String(item.role || "");
	      const displayText = normalizeControlMessageTextForDisplay(item.text, role);
	      const fullText = normalizeControlMessageTextForDisplay(item.full_text, role);
	      const compact = Boolean(options.compact);
	      const compactionPacket = Boolean(options.compactionPacket) || isContextCompactionPacket(item);
	      const hasMore = Boolean(
	        item.truncated
	        || (fullText && fullText !== displayText)
	        || (compact && compactControlMessageNeedsExpansion(displayText))
	      );
	      const expanded = Boolean(expandedControlMessages[key]);
	      const text = expanded && fullText ? fullText : displayText;
	      const useMarkdown = options.markdown !== false && role !== "tool" && role !== "error";
	      const className = `control-message-text ${useMarkdown ? "markdown" : "plain"}${expanded ? " expanded" : ""}`;
	      const body = compactionPacket && !expanded
	        ? '<div class="control-compaction-summary">Context compacted. The post-compaction packet is hidden by default.</div>'
	        : (useMarkdown
	          ? cachedMarkdownRender(`${role}\u0001${text}`, () => {
	              const jsonBody = renderJsonControlMessage(text);
	              return jsonBody || renderMarkdown(text);
	            })
	          : escapeHtml(text));
	      const button = compactionPacket && (displayText || fullText)
	        ? `<button class="control-show-more control-show-compaction-packet" type="button" data-message-key="${escapeHtml(key)}">${expanded ? "Hide post-compaction packet" : "Show post-compaction packet"}</button>`
	        : (hasMore
	          ? `<button class="control-show-more" type="button" data-message-key="${escapeHtml(key)}">${expanded ? "Show less" : "Show more"}</button>`
	          : "");
	      return `<div class="${className}" data-control-inner-scroll="${escapeHtml(`${key}:message`)}">${body}</div>${button}`;
	    }

	    function controlTranscriptGroups(items) {
	      const groups = [];
	      for (const item of items) {
	        const role = String(item.role || "message");
	        if (role === "assistant_progress" || role === "tool") {
	          const turn = String(item.turn_id || "");
	          const last = groups[groups.length - 1];
	          if (turn && last && last.kind === "assistant_activity" && String(last.turn_id || "") === turn) {
	            last.items.push(item);
	            last.updated_at = item.updated_at || item.ts || last.updated_at;
	          } else {
	            groups.push({
	              kind: "assistant_activity",
	              role: "assistant_progress",
	              turn_id: turn,
	              ts: item.ts,
	              updated_at: item.updated_at || item.ts,
	              items: [item]
	            });
	          }
	        } else {
	          groups.push({ kind: "message", item });
	        }
	      }
	      return groups;
	    }

	    function controlMessageRoleLabel(role) {
	      if (role === "resume") return "resumed context";
	      if (role === "context_compaction") return "context compaction";
	      if (role === "assistant_progress") return "assistant activity";
	      if (role === "tool") return "tool / command";
	      if (role === "user_pending") return "user";
	      return role;
	    }

	    function controlTurnMarkup(item) {
	      const turnId = String(item && item.turn_id || "");
	      if (turnId) return ` / ${escapeHtml(turnId)}`;
	      if (String(item && item.role || "") === "user_pending") {
	        return ` <span class="control-message-turn">/ <span class="control-message-spinner" aria-hidden="true"></span>pending</span>`;
	      }
	      return "";
	    }

	    function renderControlTranscriptGroup(group, index, total) {
	      const compact = index < Math.max(0, total - 5) ? " compact" : "";
	      if (group.kind === "assistant_activity") {
	        const turn = group.turn_id ? ` / ${group.turn_id}` : "";
	        const body = group.items.map((item, itemIndex) => {
	          const role = String(item.role || "");
	          if (role === "tool") {
	            return renderControlToolBlock(item, `activity-${index}-${itemIndex}`, { compact: Boolean(compact) });
	          }
	          return renderControlMessageText(item, `activity-${index}-${itemIndex}`, { compact: Boolean(compact) });
	        }).join("");
	        return `
	          <article class="control-message assistant_activity assistant_progress${compact}" data-transcript-index="${index}">
	            <div class="control-message-head">
	              <span>assistant activity${escapeHtml(turn)}</span>
	              <span>${escapeHtml(formatEventTime(group.updated_at || group.ts))}</span>
	            </div>
	            <div class="control-activity-parts">${body}</div>
	          </article>
	        `;
	      }
	      const item = group.item;
	      const role = String(item.role || "message");
	      const displayRole = controlMessageRoleLabel(role);
	      const compactionPacket = isContextCompactionPacket(item);
	      const compactByDefault = compactionPacket;
	      const messageCompact = Boolean(compact) || compactByDefault;
	      const compactClass = messageCompact ? " compact" : "";
	      return `
	        <article class="control-message ${escapeHtml(role)}${compactClass}" data-transcript-index="${index}">
	          <div class="control-message-head">
	            <span>${escapeHtml(displayRole)}${controlTurnMarkup(item)}</span>
	            <span>${escapeHtml(formatEventTime(item.updated_at || item.ts))}</span>
	          </div>
	          ${renderControlMessageText(item, `message-${index}`, { compact: messageCompact, compactionPacket })}
	        </article>
	      `;
	    }

	    function renderControlTranscript(session) {
	      const transcript = Array.isArray(session.transcript) ? session.transcript.slice() : [];
	      const turns = controlTurns(session, transcript);
	      if (!transcript.length && !turns.length) {
	        return '<div class="control-empty">No discussion text captured for this session yet</div>';
	      }
	      const turn = selectedTurnForSession(session, transcript);
	      if (!turn) {
	        return '<div class="control-empty">No observed turns for this session yet</div>';
	      }
	      if (controlSearchText && !turnMatchesSearch(transcript, turn, controlSearchText, session)) {
	        return '<div class="control-empty">No observed turns match the current search</div>';
	      }
	      let visible = [];
	      let sourceNote = "";
	      let boundaryOffsets = [];
	      let priorTurnMarkup = "";
	      if (turn.source === "history") {
	        const payload = historyTurnPayload(session, turn);
	        if (!payload) {
	          requestHistoryTurn(session, turn);
	          return '<div class="control-empty">Loading Codex session history for the selected turn...</div>';
	        }
	        visible = Array.isArray(payload.transcript) ? payload.transcript.slice() : [];
	        sourceNote = '<div class="control-transcript-window-note">Loaded from Codex session history.</div>';
	      } else {
	        if (observedTurnNeedsLoad(session, turn)) {
	          requestObservedTurn(session, turn);
	          return '<div class="control-empty">Loading earlier observed discussion for this turn...</div>';
	        }
	        const presentation = controlTurnPresentation(session, transcript, turn);
	        const activeTurn = presentation ? presentation.active : turn;
	        if (observedTurnNeedsLoad(session, activeTurn)) {
	          requestObservedTurn(session, activeTurn);
	          return '<div class="control-empty">Loading earlier observed discussion for this turn...</div>';
	        }
	        if (observedTurnHasLiveGap(session, transcript, activeTurn)) {
	          requestObservedTurn(session, activeTurn, null, true);
	        }
	        visible = turnTranscriptItems(session, transcript, activeTurn);
	        const activePayload = observedTurnPayload(session, activeTurn);
	        if (activePayload && activePayload.has_more_before) {
	          const before = Number(activePayload.next_before_index);
	          sourceNote = `<div class="control-transcript-window-note">Earlier observed discussion is available.</div><button class="control-transcript-window-button" type="button" data-control-turn-more="${escapeHtml(controlTurnKey(activeTurn))}" data-control-turn-before="${escapeHtml(before)}">Show earlier discussion</button>`;
	        }
	        if (presentation && presentation.pending) {
	          const activeIndex = presentation.turns.findIndex((candidate) => controlTurnKey(candidate) === controlTurnKey(activeTurn));
	          const pendingIndex = presentation.turns.findIndex((candidate) => controlTurnKey(candidate) === controlTurnKey(presentation.pending));
	          const bridgeTurns = activeIndex >= 0 && pendingIndex >= activeIndex
	            ? presentation.turns.slice(activeIndex, pendingIndex + 1)
	            : [activeTurn, presentation.pending];
	          visible = [];
	          for (const [index, bridgeTurn] of bridgeTurns.entries()) {
	            if (index > 0) boundaryOffsets.push(controlTranscriptGroups(visible).length);
	            visible = visible.concat(turnTranscriptItems(session, transcript, bridgeTurn));
	          }
	        } else if (presentation && presentation.state.revealedKey) {
	          const prior = controlTurnByKey(presentation.turns, presentation.state.revealedKey);
	          const priorItems = prior ? turnTranscriptItems(session, transcript, prior) : [];
	          const nextItems = turnTranscriptItems(session, transcript, activeTurn);
	          visible = priorItems.concat(nextItems);
	          boundaryOffsets = [controlTranscriptGroups(priorItems).length];
	        } else if (presentation && presentation.state.hiddenKey) {
	          const prior = controlTurnByKey(presentation.turns, presentation.state.hiddenKey);
	          if (prior) {
	            priorTurnMarkup = `
	              <div class="control-prior-turn">
	                <span>Previous turn is compacted for performance.</span>
	                <span class="control-prior-turn-actions">
	                  <button type="button" data-control-prior-show="${escapeHtml(controlTurnKey(prior))}">Show more</button>
	                  <button type="button" data-control-prior-open="${escapeHtml(controlTurnKey(prior))}">Open previous turn</button>
	                </span>
	              </div>
	            `;
	          }
	        }
	        const visibleItemIds = new Set(
	          visible.map((item, index) => controlTranscriptItemIdentity(item, index))
	        );
	        const pending = transcript.filter((item, index) => (
	          String(item.role || "") === "user_pending"
	          && !visibleItemIds.has(controlTranscriptItemIdentity(item, index))
	        ));
	        if (pending.length) visible = visible.concat(pending);
	      }
	      if (controlSearchText) {
	        const matched = visible.filter((item) => controlTranscriptMatches(item, controlSearchText));
	        if (!matched.length && !String(turn.label || "").toLowerCase().includes(controlSearchText.toLowerCase())) {
	          return '<div class="control-empty">No discussion entries in this turn match the current search</div>';
	        }
	      }
	      const groups = controlTranscriptGroups(visible);
	      const bridgeVisible = boundaryOffsets.length > 0;
	      const transcriptWindow = bridgeVisible
	        ? { start: 0, end: groups.length }
	        : controlTranscriptWindow(groups.length);
	      const windowedGroups = groups.slice(transcriptWindow.start, transcriptWindow.end);
	      const olderButton = transcriptWindow.start > 0
	        ? `<button class="control-transcript-window-button" type="button" data-control-window="above">Show ${Math.min(CONTROL_TRANSCRIPT_WINDOW_STEP, transcriptWindow.start)} older entries</button>`
	        : "";
	      const newerButton = transcriptWindow.end < groups.length
	        ? `<button class="control-transcript-window-button" type="button" data-control-window="below">Show ${Math.min(CONTROL_TRANSCRIPT_WINDOW_STEP, groups.length - transcriptWindow.end)} newer entries</button>`
	        : "";
	      const matchedTurns = controlSearchText
	        ? controlTurns(session, transcript).filter((candidate) => turnMatchesSearch(transcript, candidate, controlSearchText, session)).length
	        : 0;
	      const searchNote = matchedTurns > 1
	        ? `<div class="control-transcript-window-note">${matchedTurns} turns match. Use the turn selector to navigate.</div>`
	        : "";
	      return `
	        ${searchNote}
	        ${sourceNote}
	        ${priorTurnMarkup}
	        <div class="control-transcript" data-total="${groups.length}" data-hidden-above="${transcriptWindow.start}" data-hidden-below="${groups.length - transcriptWindow.end}">
	          ${olderButton}
	          ${windowedGroups.map((group, offset) => {
	            const index = transcriptWindow.start + offset;
	            const boundary = bridgeVisible && boundaryOffsets.includes(index)
	              ? '<div class="control-turn-boundary" data-control-turn-boundary>New turn</div>'
	              : "";
	            return `${boundary}${renderControlTranscriptGroup(group, index, groups.length)}`;
	          }).join("")}
	          ${bridgeVisible && boundaryOffsets.includes(groups.length) ? '<div class="control-turn-boundary" data-control-turn-boundary>New turn</div>' : ""}
	          ${newerButton}
	        </div>
	      `;
	    }

	    function renderControlEvents(session) {
	      const events = Array.isArray(session.events) ? session.events.slice().reverse() : [];
	      if (!events.length) {
	        return '<div class="control-empty">No recorded activity for this session yet</div>';
	      }
	      return `<div class="control-events">${events.map((event) => {
	        const summary = event.summary || statsEventText(event);
	        const profile = event.profile ? `<span>Profile: ${escapeHtml(event.profile)}</span>` : "";
	        const type = event.type ? `<span>Type: ${escapeHtml(event.type)}</span>` : "";
	        const tier = event.service_tier ? `<span>Tier: ${escapeHtml(event.service_tier)}</span>` : "";
	        return `
	          <div class="control-event compact">
	            <span>${escapeHtml(formatEventTime(event.ts))}</span>
	            <div class="control-event-detail">
	              <strong>${escapeHtml(summary)}</strong>
	              ${profile}
	              ${type}
	              ${tier}
	            </div>
	          </div>
	        `;
	      }).join("")}</div>`;
	    }

	    function sessionAssociatedProfile(session) {
	      return String((session && (session.associated_profile || session.pinned_profile || session.last_profile)) || "");
	    }

	    function sessionIsLive(session) {
	      if (!session) return false;
	      if (session.pty_control_available || session.ui_launcher_running || session.active) return true;
	      if (Number(session.active_requests || 0) > 0) return true;
	      if (Number(session.active_tunnels || 0) > 0) return true;
	      if (Number(session.pending_websocket_work || 0) > 0) return true;
	      return false;
	    }

	    function updateControlHeaderActions(session) {
	      const turnSelect = document.getElementById("controlTurnSelect");
	      const forget = document.getElementById("controlForget");
	      const approvals = document.getElementById("controlPermissionsToggle");
	      if (!turnSelect || !forget || !approvals) return;
	      const connected = socket && socket.readyState === WebSocket.OPEN;
	      const turns = session ? controlTurns(session, Array.isArray(session.transcript) ? session.transcript : []) : [];
	      if (!controlTurnSelectInteracting && document.activeElement !== turnSelect) {
	        const nextOptions = session ? renderControlTurnOptions(session) : '<option value="">No observed turns</option>';
	        turnSelect.innerHTML = nextOptions;
	      }
	      turnSelect.disabled = !turns.length;
	      turnSelect.hidden = controlView !== "discussion";
	      forget.disabled = !connected || !session;
	      forget.title = sessionIsLive(session)
	        ? "Close the associated launcher and forget this live session"
	        : "Forget this idle observed session";
	      const permissionSupported = Boolean(session && session.permission_routing_supported);
	      const permissionEnabled = Boolean(permissionSupported && session.permission_routing_enabled);
	      approvals.hidden = !permissionSupported;
	      approvals.disabled = !connected || !permissionSupported;
	      approvals.setAttribute("aria-pressed", permissionEnabled ? "true" : "false");
	      approvals.textContent = permissionSupported
	        ? `Approvals: ${permissionEnabled ? "browser" : "terminal"}`
	        : "Approvals unavailable";
	      approvals.title = String(session && session.permission_routing_reason || "");
	    }

	    function permissionRequests(state = latestPermissions) {
	      const requests = state && Array.isArray(state.pending) ? state.pending : [];
	      return requests.filter((request) => request && typeof request === "object");
	    }

	    function renderPermissionModal() {
	      const modal = document.getElementById("permissionModal");
	      if (!modal) return;
	      const connected = Boolean(socket && socket.readyState === WebSocket.OPEN);
	      const requests = permissionRequests();
	      const request = requests[0];
	      if (!connected || !request) {
	        modal.hidden = true;
	        pendingPermissionDecision = "";
	        return;
	      }
	      const requestId = String(request.request_id || "");
	      if (pendingPermissionDecision && pendingPermissionDecision !== requestId) {
	        pendingPermissionDecision = "";
	      }
	      const provider = String(request.provider || "provider");
	      const workspace = String(request.workspace || request.session_key || "session");
	      document.getElementById("permissionProvider").textContent = `${provider} · ${workspace}`;
	      document.getElementById("permissionTool").textContent = String(request.tool_name || "Tool");
	      document.getElementById("permissionCategory").textContent = String(request.category || "tool");
	      document.getElementById("permissionReason").textContent = String(request.reason || "");
	      document.getElementById("permissionPreview").textContent = String(request.preview || "");
	      document.getElementById("permissionQueueCount").textContent = requests.length > 1
	        ? `${requests.length} pending`
	        : "1 pending";
	      for (const id of ["permissionTerminal", "permissionDeny", "permissionAllow"]) {
	        document.getElementById(id).disabled = Boolean(pendingPermissionDecision);
	      }
	      modal.dataset.requestId = requestId;
	      modal.dataset.sessionKey = String(request.session_key || "");
	      modal.hidden = false;
	    }

	    function resolvePermission(decision) {
	      const modal = document.getElementById("permissionModal");
	      if (!modal || modal.hidden || pendingPermissionDecision) return;
	      if (!socket || socket.readyState !== WebSocket.OPEN) return;
	      const requestId = String(modal.dataset.requestId || "");
	      const sessionKey = String(modal.dataset.sessionKey || "");
	      if (!requestId || !sessionKey) return;
	      pendingPermissionDecision = requestId;
	      renderPermissionModal();
	      socket.send(JSON.stringify({
	        action: "resolve_permission",
	        request_id: requestId,
	        session_key: sessionKey,
	        decision,
	      }));
	    }

	    function sendLaunchSession(sessionKey, mode, sessionId = "") {
	      if (!sessionKey || !socket || socket.readyState !== WebSocket.OPEN) return;
	      const sessions = controlSessions({ control_plane: latestControlPlane });
	      const session = sessions.find((item) => item.key === sessionKey) || {};
	      socket.send(JSON.stringify({
	        action: "launch_session",
	        session_key: sessionKey,
	        profile: sessionAssociatedProfile(session),
	        mode,
	        session_id: sessionId,
	        permission: launcherPermission,
	      }));
	    }

	    function selectedResumeCandidateId(session) {
	      const key = String(session && session.key || selectedControlSessionKey || "");
	      const candidates = resumeCandidatesForSession(session);
	      const selected = selectedResumeCandidateIds[key] || "";
	      if (selected && candidates.some((candidate) => String(candidate.id || "") === selected)) return selected;
	      const fallback = candidates.length ? String(candidates[0].id || "") : "";
	      selectedResumeCandidateIds[key] = fallback;
	      return fallback;
	    }

	    function renderResumePane(session) {
	      const candidates = resumeCandidatesForSession(session);
	      if (!candidates.length) {
	        return '<div class="control-empty">No resumable Codex CLI sessions were found for this workdir.</div>';
	      }
	      const selectedId = selectedResumeCandidateId(session);
	      const rows = candidates.map((candidate) => {
	        const id = String(candidate.id || "");
	        const when = candidate.timestamp ? formatEventTime(candidate.timestamp) : "";
	        const selected = id === selectedId ? " selected" : "";
	        const label = candidate.label || id;
	        return `
	          <button class="control-resume-item${selected}" type="button" data-resume-candidate="${escapeHtml(id)}">
	            <span class="control-resume-main">
	              <span class="control-resume-label">${escapeHtml(label)}</span>
	              <span class="control-resume-meta">${escapeHtml([when, id].filter(Boolean).join(" / "))}</span>
	            </span>
	            <span class="badge">${id === selectedId ? "Selected" : "Choose"}</span>
	          </button>
	        `;
	      }).join("");
	      const disabled = !selectedId || !socket || socket.readyState !== WebSocket.OPEN ? "disabled" : "";
	      return `
	        <section class="control-detail-section">
	          <h3>Resume Session</h3>
	          <div class="control-section-body">
	            <div class="control-resume-list">${rows}</div>
	            <div class="control-resume-actions">
	              <button type="button" data-resume-action="resume-session" ${disabled}>Resume</button>
	              <button type="button" data-resume-action="fork-session" ${disabled}>Fork</button>
	            </div>
	          </div>
	        </section>
	      `;
	    }

	    function renderControlModal(force = false) {
	      const modal = document.getElementById("controlModal");
	      if (!modal || modal.hidden) return;
	      if (!force && controlRenderShouldDefer()) {
	        if (!controlRenderDeferredAt) controlRenderDeferredAt = Date.now();
	        if (Date.now() - controlRenderDeferredAt < 2000) {
	          pendingControlRender = true;
	          scheduleControlRenderFlush();
	          return;
	        }
	      }
	      controlRenderDeferredAt = 0;
	      const session = selectedControlSession();
	      if (!session) {
	        modal.hidden = true;
	        clearTerminalSnapshotRefresh();
	        resetMobileComposerFocus();
	        syncDiscussionPaneVisibility();
	        renderMobileControlStatus(null);
	        return;
	      }
	      if (controlView !== "discussion" && mobileDiscussionFocused) {
	        resetMobileDiscussionFocus();
	      }
	      if (controlView !== "discussion") resetMobileComposerFocus();
	      syncDiscussionPaneVisibility();
	      const provider = String(session.provider || "codex");
	      if (provider !== "codex" && controlView === "resume") controlView = "discussion";
	      if (controlView !== "terminal") clearTerminalSnapshotRefresh();
	      if (provider === "codex") requestHistoryIndex(session);
	      if (controlView === "resume" && provider === "codex") requestResumeCandidates(session);
	      if (controlView === "terminal") requestTerminalSnapshot(session);
	      updateControlDockGeometry();
	      document.getElementById("controlTitle").textContent = String(session.cwd || session.display || sessionTitle(session));
	      const active = Number(session.active_requests || 0);
	      const tunnels = Number(session.active_tunnels || 0);
	      const pending = Number(session.pending_websocket_work || 0);
	      const associatedProfile = sessionAssociatedProfile(session) || "native";
	      const sessionWorking = Boolean(session.working)
	        || Number(session.active_turn_requests || 0) > 0
	        || pending > 0;
	      const activeState = sessionWorking ? "Working" : (session.active ? "Connected" : "Idle");
	      const pills = [
	        `<span class="pill">Provider <strong>${escapeHtml(provider)}</strong></span>`,
	        `<span class="pill">${escapeHtml(session.pinned_profile ? `Pinned ${session.pinned_profile}` : `Profile ${associatedProfile}`)}</span>`,
	        `<span class="pill">Requests <strong>${active}</strong></span>`,
	        `<span class="pill">Tunnels <strong>${tunnels}</strong></span>`,
	        `<span class="pill">Turns <strong>${pending}</strong></span>`,
	        `<span class="pill">${activeState}</span>`
	      ];
	      if (session.provider_model) {
	        pills.splice(1, 0, `<span class="pill">Model <strong>${escapeHtml(session.provider_model)}</strong></span>`);
	      }
	      if (session.context && session.context.label) {
	        const contextTitle = [
	          session.context.input_tokens ? `${formatNumber(session.context.input_tokens)} input tokens` : "",
	          session.context.remaining_tokens ? `${formatNumber(session.context.remaining_tokens)} tokens remaining` : "",
	          session.context.updated_at ? `Updated ${formatEventTime(session.context.updated_at)}` : ""
	        ].filter(Boolean).join(" / ");
	        pills.push(`<span class="pill" title="${escapeHtml(contextTitle)}">Context <strong>${escapeHtml(session.context.label)}</strong></span>`);
	      }
	      if (session.quota_compact_html) pills.push(String(session.quota_compact_html));
	      document.getElementById("controlStatusPills").innerHTML = pills.join("");
	      renderMobileControlStatus(session);
	      const panel = modal.querySelector(".control-modal");
	      if (panel) {
	        panel.classList.toggle("details-view", controlView === "details");
	        panel.classList.toggle("resume-view", controlView === "resume");
	        panel.classList.toggle("discussion-view", controlView === "discussion");
	        panel.classList.toggle("terminal-view", controlView === "terminal");
	      }
	      const workingState = document.getElementById("controlWorkingState");
	      if (workingState) {
	        workingState.hidden = controlView !== "discussion" || !sessionWorking;
	        workingState.classList.toggle("active", controlView === "discussion" && sessionWorking);
	      }
	      const search = document.getElementById("controlSearch");
	      if (search) search.hidden = controlView !== "discussion";
	      const resumeView = document.getElementById("controlResumeView");
	      if (resumeView) resumeView.hidden = provider !== "codex";
	      document.querySelectorAll("[data-control-view]").forEach((button) => {
	        button.classList.toggle("active", button.dataset.controlView === controlView);
	        button.setAttribute("aria-selected", button.dataset.controlView === controlView ? "true" : "false");
	      });
	      const content = document.getElementById("controlContent");
	      const nextScrollKey = controlScrollKey();
	      const sameScrollSurface = renderedControlScrollKey === nextScrollKey;
	      const shouldFollowDiscussion = !preserveControlScrollOnNextRender
	        && controlView === "discussion"
	        && !controlSearchText
	        && (!sameScrollSurface || controlContentAtBottom(content));
	      if (sameScrollSurface) {
	        saveControlScroll();
	        saveControlInnerScroll();
	      }
	      if (controlView === "details") {
	        content.innerHTML = `
	          <section class="control-detail-section">
	            <h3>Active Turn State</h3>
	            <div class="control-section-body">${renderControlActiveDetails(session)}</div>
	          </section>
	          <section class="control-detail-section">
	            <h3>Session Activity</h3>
	            <div class="control-section-body">${renderControlEvents(session)}</div>
	          </section>
	        `;
	      } else if (controlView === "resume") {
	        content.innerHTML = renderResumePane(session);
	      } else if (controlView === "terminal") {
	        content.innerHTML = renderControlTerminal(session);
	      } else {
	        content.innerHTML = renderControlTranscript(session);
	      }
	      normalizeNativeTooltips(modal);
	      renderedControlScrollKey = nextScrollKey;
	      if (shouldFollowDiscussion) {
	        content.scrollTop = content.scrollHeight;
	      } else {
	        restoreControlScroll();
	      }
	      requestAnimationFrame(restoreControlInnerScroll);
	      updateControlComposeState(session);
	      updateControlHeaderActions(session);
	      requestAnimationFrame(() => {
	        updateControlScrollBadges();
	        finalizeControlTurnBridgeIfScrolledAway();
	      });
	      preserveControlScrollOnNextRender = false;
	      pendingControlRender = false;
	    }

	    function statsProfileColor(index) {
	      const colors = ["#d83434", "#198754", "#2563eb", "#b7791f", "#7c3aed", "#0891b2", "#be185d"];
	      return colors[index % colors.length];
	    }

	    function statsProfiles(stats) {
	      const names = new Set();
	      for (const profile of Array.isArray(stats.profiles) ? stats.profiles : []) {
	        if (profile && profile.profile) names.add(String(profile.profile));
	      }
	      for (const point of Array.isArray(stats.series) ? stats.series : []) {
	        if (point && point.profile) names.add(String(point.profile));
	      }
	      return Array.from(names).sort();
	    }

	    function syncStatsVisibleProfiles(profiles) {
	      for (const profile of profiles) {
	        if (!(profile in statsVisibleProfiles)) statsVisibleProfiles[profile] = true;
	      }
	    }

	    function renderStatsGraph(stats, profiles) {
	      const series = Array.isArray(stats.series) ? stats.series : [];
	      const activeProfiles = profiles.filter((profile) => statsVisibleProfiles[profile]);
	      const points = series
	        .filter((point) => activeProfiles.includes(String(point.profile || "")))
	        .map((point) => ({
	          profile: String(point.profile || "unknown"),
	          ts: Date.parse(point.ts || ""),
	          value: Number(point.value || 0),
	          tokens: Number(point.tokens || 0),
	          traffic: Number(point.traffic || 0),
	          requests: Number(point.requests || 0),
	          quotaUpdates: Number(point.quota_updates || 0)
	        }))
	        .filter((point) => Number.isFinite(point.ts) && Number.isFinite(point.value));
	      if (!points.length) {
	        return '<div class="stats-graph-empty">No usage activity recorded yet</div>';
	      }
	      const minTs = Math.min(...points.map((point) => point.ts));
	      const maxTs = Math.max(...points.map((point) => point.ts));
	      const maxValue = Math.max(1, ...points.map((point) => point.value));
	      const width = 1000;
	      const height = 230;
	      const padLeft = 54;
	      const padRight = 24;
	      const padTop = 22;
	      const padBottom = 34;
	      const plotRight = width - padRight;
	      const plotBottom = height - padBottom;
	      const usableWidth = width - padLeft - padRight;
	      const usableHeight = height - padTop - padBottom;
	      const xFor = (ts) => padLeft + (maxTs === minTs ? usableWidth : ((ts - minTs) / (maxTs - minTs)) * usableWidth);
	      const yFor = (value) => padTop + usableHeight - (value / maxValue) * usableHeight;
	      const timeLabel = (ts) => new Date(ts).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
	      const yTicks = [0, maxValue / 2, maxValue];
	      const xTicks = maxTs === minTs ? [minTs] : [minTs, minTs + (maxTs - minTs) / 2, maxTs];
	      const yGrid = yTicks.map((value) => {
	        const y = yFor(value);
	        return `
	          <path class="stats-graph-grid" d="M${padLeft} ${y.toFixed(1)}H${width - padRight}"></path>
	          <text class="stats-graph-label" x="${padLeft - 8}" y="${(y + 4).toFixed(1)}" text-anchor="end">${escapeHtml(formatNumber(Math.round(value)))}</text>
	        `;
	      }).join("");
	      const xGrid = xTicks.map((ts) => {
	        const x = xFor(ts);
	        return `
	          <path class="stats-graph-grid" d="M${x.toFixed(1)} ${padTop}V${height - padBottom}"></path>
	          <text class="stats-graph-label" x="${x.toFixed(1)}" y="${height - 10}" text-anchor="${ts === minTs ? "start" : ts === maxTs ? "end" : "middle"}">${escapeHtml(timeLabel(ts))}</text>
	        `;
	      }).join("");
	      const referenceY = yFor(maxValue);
	      const reference = `
	        <path class="stats-graph-reference" d="M${padLeft} ${referenceY.toFixed(1)}H${width - padRight}"></path>
	        <text class="stats-graph-label" x="${width - padRight}" y="${(referenceY - 6).toFixed(1)}" text-anchor="end">peak ${escapeHtml(formatNumber(Math.round(maxValue)))}</text>
	      `;
	      const grouped = new Map();
	      for (const point of points) {
	        if (!grouped.has(point.profile)) grouped.set(point.profile, []);
	        grouped.get(point.profile).push(point);
	      }
	      const lines = Array.from(grouped.entries()).map(([profile, rows]) => {
	        const profileIndex = profiles.indexOf(profile);
	        const color = statsProfileColor(profileIndex < 0 ? 0 : profileIndex);
	        const sorted = rows.slice().sort((a, b) => a.ts - b.ts);
	        const path = sorted.map((point, index) => {
	          const x = xFor(point.ts);
	          const y = yFor(point.value);
	          return `${index ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`;
	        }).join(" ");
	        const latest = sorted[sorted.length - 1];
	        const marker = latest
	          ? `<circle class="stats-graph-marker" cx="${xFor(latest.ts).toFixed(1)}" cy="${yFor(latest.value).toFixed(1)}" r="4.2" fill="${color}"></circle>`
	          : "";
	        return `
	          <path d="${path}" fill="none" stroke="${color}" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"></path>
	          ${marker}
	        `;
	      }).join("");
	      const interactivePoints = points.map((point) => {
	        const profileIndex = profiles.indexOf(point.profile);
	        return {
	          profile: point.profile,
	          ts: point.ts,
	          time: timeLabel(point.ts),
	          value: point.value,
	          tokens: point.tokens,
	          traffic: point.traffic,
	          requests: point.requests,
	          quotaUpdates: point.quotaUpdates,
	          x: xFor(point.ts),
	          y: yFor(point.value),
	          color: statsProfileColor(profileIndex < 0 ? 0 : profileIndex)
	        };
	      });
	      return `
	        <svg class="stats-graph-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Profile usage trend" data-points="${escapeHtml(JSON.stringify(interactivePoints))}" data-width="${width}" data-height="${height}" data-plot-left="${padLeft}" data-plot-right="${plotRight}" data-plot-top="${padTop}" data-plot-bottom="${plotBottom}">
	          ${yGrid}
	          ${xGrid}
	          <path class="stats-graph-axis" d="M${padLeft} ${height - padBottom}H${width - padRight}"></path>
	          <path class="stats-graph-axis" d="M${padLeft} ${padTop}V${height - padBottom}"></path>
	          ${reference}
	          ${lines}
	        </svg>
	        <div class="stats-graph-cursor" hidden></div>
	        <div class="stats-graph-hover-dot" hidden></div>
	        <div class="stats-graph-tooltip" hidden></div>
	      `;
	    }

	    function statsGraphData(graph) {
	      const svg = graph ? graph.querySelector(".stats-graph-svg") : null;
	      if (!svg) return null;
	      let points = [];
	      try {
	        points = JSON.parse(svg.dataset.points || "[]");
	      } catch {
	        points = [];
	      }
	      if (!Array.isArray(points) || !points.length) return null;
	      const bounds = svg.getBoundingClientRect();
	      const width = Number(svg.dataset.width || 1000);
	      const height = Number(svg.dataset.height || 230);
	      if (!bounds.width || !bounds.height || !width || !height) return null;
	      const plot = {
	        left: Number(svg.dataset.plotLeft || 0),
	        right: Number(svg.dataset.plotRight || width),
	        top: Number(svg.dataset.plotTop || 0),
	        bottom: Number(svg.dataset.plotBottom || height)
	      };
	      return { svg, points, bounds, width, height, plot };
	    }

	    function nearestStatsPoint(graph, clientX, clientY) {
	      const data = statsGraphData(graph);
	      if (!data) return null;
	      const x = ((clientX - data.bounds.left) / data.bounds.width) * data.width;
	      const y = ((clientY - data.bounds.top) / data.bounds.height) * data.height;
	      if (
	        x < data.plot.left ||
	        x > data.plot.right ||
	        y < data.plot.top ||
	        y > data.plot.bottom
	      ) {
	        return null;
	      }
	      let best = null;
	      let bestScore = Infinity;
	      for (const point of data.points) {
	        const dx = Number(point.x || 0) - x;
	        const dy = Number(point.y || 0) - y;
	        const score = Math.abs(dx) * 2 + Math.abs(dy);
	        if (score < bestScore) {
	          best = point;
	          bestScore = score;
	        }
	      }
	      if (!best) return null;
	      return { point: best, data };
	    }

	    function statsGraphTooltipHtml(point) {
	      const traffic = Number(point.traffic || 0);
	      const value = Number(point.value || 0);
	      const tokens = Number(point.tokens || 0);
	      const pieces = [
	        `<strong>${escapeHtml(point.profile || "unknown")}</strong>`,
	        `<span>${escapeHtml(point.time || "")}</span>`
	      ];
	      if (tokens) pieces.push(`<span>Tokens: ${escapeHtml(formatNumber(tokens))}</span>`);
	      if (value && value !== tokens) pieces.push(`<span>Trend value: ${escapeHtml(formatNumber(value))}</span>`);
	      if (traffic) pieces.push(`<span>Traffic: ${escapeHtml(formatBytes(traffic))}</span>`);
	      if (Number(point.requests || 0)) pieces.push(`<span>Requests: ${escapeHtml(formatNumber(point.requests))}</span>`);
	      if (Number(point.quotaUpdates || 0)) pieces.push(`<span>Quota updates: ${escapeHtml(formatNumber(point.quotaUpdates))}</span>`);
	      return pieces.join("");
	    }

	    function updateStatsGraphHover(graph, event) {
	      const nearest = nearestStatsPoint(graph, event.clientX, event.clientY);
	      if (!nearest) {
	        hideStatsGraphHover(graph);
	        return;
	      }
	      const { point, data } = nearest;
	      const cursor = graph.querySelector(".stats-graph-cursor");
	      const dot = graph.querySelector(".stats-graph-hover-dot");
	      const tooltip = graph.querySelector(".stats-graph-tooltip");
	      if (!cursor || !dot || !tooltip) return;
	      const left = (Number(point.x || 0) / data.width) * data.bounds.width;
	      const top = (Number(point.y || 0) / data.height) * data.bounds.height;
	      cursor.hidden = false;
	      dot.hidden = false;
	      tooltip.hidden = false;
	      cursor.style.left = `${left}px`;
	      dot.style.left = `${left}px`;
	      dot.style.top = `${top}px`;
	      dot.style.background = point.color || "";
	      tooltip.innerHTML = statsGraphTooltipHtml(point);
	      const tooltipWidth = tooltip.offsetWidth || 220;
	      const tooltipHeight = tooltip.offsetHeight || 96;
	      const preferredLeft = left > data.bounds.width * 0.58 ? left - tooltipWidth - 12 : left + 12;
	      const tooltipLeft = Math.max(8, Math.min(data.bounds.width - tooltipWidth - 8, preferredLeft));
	      const tooltipTop = Math.max(8, Math.min(data.bounds.height - tooltipHeight - 8, top - 42));
	      tooltip.style.left = `${tooltipLeft}px`;
	      tooltip.style.top = `${tooltipTop}px`;
	    }

	    function hideStatsGraphHover(graph) {
	      for (const selector of [".stats-graph-cursor", ".stats-graph-hover-dot", ".stats-graph-tooltip"]) {
	        const node = graph ? graph.querySelector(selector) : null;
	        if (node) node.hidden = true;
	      }
	    }

		    function setStatsOpen(open) {
		      const modal = document.getElementById("statsModal");
		      const toggle = document.getElementById("statsToggle");
		      if (!modal) return;
		      updateControlDockGeometry();
		      modal.hidden = !open;
		      if (toggle) toggle.classList.toggle("active", Boolean(open));
		      if (open) renderStats(latestStats);
		    }

	    function renderStats(stats) {
	      const content = document.getElementById("statsContent");
	      if (!content) return;
	      const contentScroll = scrollSnapshot(content);
	      const recentScroll = scrollSnapshot(content.querySelector(".stats-recent"));
	      const profiles = Array.isArray(stats.profiles) ? stats.profiles : [];
	      const profileNames = statsProfiles(stats);
	      syncStatsVisibleProfiles(profileNames);
	      const toggles = profileNames.map((profile, index) => `
	        <label class="stats-profile-toggle">
	          <input type="checkbox" class="stats-profile-check" value="${escapeHtml(profile)}" ${statsVisibleProfiles[profile] ? "checked" : ""}>
	          <span style="--profile-color: ${statsProfileColor(index)}"></span>
	          ${escapeHtml(profile)}
	        </label>
	      `).join("");
	      const rows = profiles.length ? profiles.map((profile) => {
	        const traffic = `Up ${formatBytes(profile.bytes_up)} / Down ${formatBytes(profile.bytes_down)}`;
	        const activeTunnels = Number(profile.active_tunnels || 0);
	        const tunnelCount = activeTunnels
	          ? `${formatNumber(profile.tunnels)} closed / ${formatNumber(activeTunnels)} active`
	          : formatNumber(profile.tunnels);
	        const tokens = `${formatNumber(profile.total_tokens)} total (${formatNumber(profile.input_tokens)} in, ${formatNumber(profile.output_tokens)} out)`;
	        const fast = `${formatNumber(profile.fast_turns)} events / ${formatNumber(profile.fast_tokens)} tokens`;
	        const quota = quotaDeltaText(profile.last_quota) || "-";
	        return `
	          <tr>
	            <td>${escapeHtml(profile.profile || "unknown")}</td>
	            <td>${formatNumber(profile.requests)}</td>
	            <td>${escapeHtml(tunnelCount)}</td>
	            <td>${escapeHtml(traffic)}</td>
	            <td>${escapeHtml(tokens)}</td>
	            <td>${escapeHtml(fast)}</td>
	            <td>${formatNumber(profile.quota_updates)}</td>
	            <td>${escapeHtml(quota)}</td>
	          </tr>
	        `;
	      }).join("") : '<tr><td colspan="8">No stats recorded yet</td></tr>';
	      const recent = Array.isArray(stats.recent) ? stats.recent.slice() : [];
	      const recentHtml = recent.length ? recent.map((event) => `
	        <div class="stats-event">
	          <span>${escapeHtml(formatEventTime(event.ts))}</span>
	          <strong>${escapeHtml(statsEventText(event))}</strong>
	        </div>
	      `).join("") : '<div class="stats-event"><span></span><strong>No recent events</strong></div>';
	      content.innerHTML = `
	        <section class="stats-graph-card">
	          <div class="stats-graph-head">
	            <h3>Usage Trend</h3>
	            <div class="stats-profile-toggles">${toggles}</div>
	          </div>
	          <div class="stats-graph">${renderStatsGraph(stats, profileNames)}</div>
	        </section>
	        <section class="stats-section">
	          <h3>Profiles</h3>
	          <div class="stats-table-wrap">
	            <table class="stats-table">
	              <thead>
	                <tr>
	                  <th>Profile</th>
	                  <th>Requests</th>
	                  <th>Tunnels</th>
	                  <th>Traffic</th>
	                  <th>Tokens</th>
	                  <th>Fast</th>
	                  <th>Quota</th>
	                  <th>Last Movement</th>
	                </tr>
	              </thead>
	              <tbody>${rows}</tbody>
	            </table>
	          </div>
	        </section>
	        <section class="stats-section">
	          <h3>Recent Activity</h3>
	          <div class="stats-recent">${recentHtml}</div>
	        </section>
		      `;
	      normalizeNativeTooltips(content);
	      restoreScrollSnapshot(content, contentScroll);
	      restoreScrollSnapshot(content.querySelector(".stats-recent"), recentScroll);
		    }

		    function showUiMessage(text) {
		      const message = document.getElementById("message");
		      if (!message) return;
		      if (text) {
		        message.textContent = text;
		        message.classList.add("visible");
		      } else {
		        message.textContent = "";
		        message.classList.remove("visible");
		      }
		    }

	    function closeConfirmation(result) {
	      const modal = document.getElementById("confirmModal");
	      if (modal) modal.hidden = true;
	      if (pendingConfirmation) {
	        const pending = pendingConfirmation;
	        pendingConfirmation = null;
	        const resolution = typeof pending.resolveResult === "function"
	          ? pending.resolveResult(Boolean(result))
	          : Boolean(result);
	        pending.resolve(resolution);
	      }
	    }

	    function clearConfirmationDetails() {
	      const details = document.getElementById("confirmDetails");
	      if (!details) return;
	      details.hidden = true;
	      details.replaceChildren();
	    }

	    function confirmAction({ title = "Confirm action", message = "", acceptLabel = "Confirm", danger = true } = {}) {
	      const modal = document.getElementById("confirmModal");
	      const titleNode = document.getElementById("confirmTitle");
	      const messageNode = document.getElementById("confirmMessage");
	      const accept = document.getElementById("confirmAccept");
	      const cancel = document.getElementById("confirmCancel");
	      if (!modal || !titleNode || !messageNode || !accept || !cancel) {
	        return Promise.resolve(false);
	      }
	      if (pendingConfirmation) closeConfirmation(false);
	      titleNode.textContent = title;
	      messageNode.textContent = message;
	      clearConfirmationDetails();
	      accept.textContent = acceptLabel;
	      accept.classList.toggle("danger", Boolean(danger));
	      modal.hidden = false;
	      accept.focus();
	      return new Promise((resolve) => {
	        pendingConfirmation = { resolve };
	      });
	    }

	    function resetCreditTimeLabel(value) {
	      const moment = new Date(String(value || ""));
	      if (Number.isNaN(moment.getTime())) return "Not reported";
	      return moment.toLocaleString(undefined, {
	        year: "numeric",
	        month: "short",
	        day: "numeric",
	        hour: "numeric",
	        minute: "2-digit",
	        timeZoneName: "short"
	      });
	    }

	    function usableResetCredits(value) {
	      if (!Array.isArray(value)) return [];
	      const seen = new Set();
	      return value.flatMap((credit) => {
	        if (!credit || typeof credit !== "object") return [];
	        const id = String(credit.id || "").trim();
	        if (!id || id.length > 512 || seen.has(id)) return [];
	        seen.add(id);
	        return [{
	          id,
	          issued_at: String(credit.issued_at || ""),
	          expires_at: String(credit.expires_at || "")
	        }];
	      });
	    }

	    function chooseResetCredit(credits) {
	      const modal = document.getElementById("confirmModal");
	      const titleNode = document.getElementById("confirmTitle");
	      const messageNode = document.getElementById("confirmMessage");
	      const details = document.getElementById("confirmDetails");
	      const accept = document.getElementById("confirmAccept");
	      const cancel = document.getElementById("confirmCancel");
	      if (!modal || !titleNode || !messageNode || !details || !accept || !cancel) {
	        return Promise.resolve(null);
	      }
	      if (pendingConfirmation) closeConfirmation(false);
	      const available = usableResetCredits(credits);
	      titleNode.textContent = "Use reset credit";
	      messageNode.textContent = "Choose a specific credit, or leave Automatic selected to use the available credit with the nearest expiration time.";
	      const choices = [
	        `<label class="reset-credit-choice automatic">
	          <input type="radio" name="reset-credit-choice" value="" checked>
	          <span><strong>Automatic</strong><span>Use the available reset credit with the nearest expiration time.</span></span>
	        </label>`
	      ];
	      for (const [index, credit] of available.entries()) {
	        const issued = resetCreditTimeLabel(credit.issued_at);
	        const expires = resetCreditTimeLabel(credit.expires_at);
	        choices.push(`<label class="reset-credit-choice">
	          <input type="radio" name="reset-credit-choice" value="${escapeHtml(credit.id)}">
	          <span><strong>Credit ${index + 1}</strong><span>Reference: ${escapeHtml(credit.id)}</span><span>Issued: ${escapeHtml(issued)}</span><span>Expires: ${escapeHtml(expires)}</span></span>
	        </label>`);
	      }
	      details.innerHTML = `
	        <p class="reset-credit-picker-note">${available.length
	          ? "Available reset credits are listed below."
	          : "Detailed credit records are not available yet. Automatic selection will be used."}</p>
	        <div class="reset-credit-picker-list">${choices.join("")}</div>`;
	      details.hidden = false;
	      accept.textContent = "Use credit";
	      accept.classList.add("danger");
	      modal.hidden = false;
	      accept.focus();
	      return new Promise((resolve) => {
	        pendingConfirmation = {
	          resolve,
	          resolveResult: (accepted) => {
	            if (!accepted) return null;
	            const selected = details.querySelector('input[name="reset-credit-choice"]:checked');
	            return { creditId: selected ? String(selected.value || "") : "" };
	          }
	        };
	      });
	    }

	    function normalizeNativeTooltips(root = document) {
	      if (!root || !root.querySelectorAll) return;
	      root.querySelectorAll("[title]").forEach((node) => {
		        const text = node.getAttribute("title") || "";
		        node.removeAttribute("title");
		        if (!text) return;
		        node.setAttribute("data-tooltip", text);
		        if (!node.getAttribute("aria-label") && !node.textContent.trim()) {
		          node.setAttribute("aria-label", text);
		        }
	      });
	    }

	    function uiTooltipTarget(target) {
	      if (!(target instanceof Element)) return null;
		      const node = target.closest("[data-tooltip], [title]");
		      if (!node) return null;
		      if (node.hasAttribute("title")) normalizeNativeTooltips(node.parentElement || document);
		      return node.getAttribute("data-tooltip") ? node : null;
	    }

	    function positionUiTooltip(event, target) {
	      const tooltip = document.getElementById("uiTooltip");
	      if (!tooltip || tooltip.hidden) return;
	      const rect = target.getBoundingClientRect();
	      const baseX = typeof event.clientX === "number" ? event.clientX : rect.left + rect.width / 2;
	      const baseY = typeof event.clientY === "number" ? event.clientY : rect.bottom;
	      const left = Math.max(8, Math.min(window.innerWidth - tooltip.offsetWidth - 8, baseX + 12));
	      const top = Math.max(8, Math.min(window.innerHeight - tooltip.offsetHeight - 8, baseY + 14));
	      tooltip.style.left = `${left}px`;
	      tooltip.style.top = `${top}px`;
	    }

	    function showUiTooltip(event) {
	      const target = uiTooltipTarget(event.target);
	      const tooltip = document.getElementById("uiTooltip");
	      if (!target || !tooltip) return;
	      tooltip.textContent = target.getAttribute("data-tooltip") || "";
	      if (!tooltip.textContent) return;
	      tooltip.hidden = false;
	      positionUiTooltip(event, target);
	    }

	    function hideUiTooltip() {
	      const tooltip = document.getElementById("uiTooltip");
	      if (tooltip) tooltip.hidden = true;
	    }

	    function setConnection(label, state) {
	      const text = label === "Live" ? `Live (${latestLiveBusy ? "busy" : "idle"})` : label;
	      document.getElementById("connectionState").textContent = text;
	      const dot = document.getElementById("proxyDot");
	      dot.className = "dot" + (state ? " " + state : "");
	    }

	    function savedTheme() {
	      try {
	        const value = localStorage.getItem(THEME_KEY);
	        return value === "light" || value === "dark" ? value : null;
	      } catch {
	        return null;
	      }
	    }

	    function systemTheme() {
	      return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
	    }

	    function effectiveTheme() {
	      return savedTheme() || systemTheme();
	    }

	    function setTheme(theme) {
	      document.documentElement.dataset.theme = theme;
	      try {
	        localStorage.setItem(THEME_KEY, theme);
	      } catch {
	      }
	      updateThemeToggle();
	    }

	    function updateThemeToggle() {
	      const button = document.getElementById("themeToggle");
	      if (!button) return;
	      const current = effectiveTheme();
	      const target = current === "dark" ? "light" : "dark";
	      button.innerHTML = target === "dark" ? MOON_ICON : SUN_ICON;
	      button.title = `Switch to ${target} mode`;
	      button.setAttribute("aria-label", `Switch to ${target} mode`);
	    }

	    function openMenuProfile(selector) {
	      const openMenu = document.querySelector(`${selector}[open]`);
	      return openMenu ? openMenu.dataset.profile || "" : null;
	    }

	    function rememberOpenMenus() {
	      openPinMenuProfile = openMenuProfile("details.pin-menu");
	      openModelMenuProfile = openMenuProfile("details.model-menu");
	      openLoginMenuProfile = openMenuProfile("details.login-menu");
	      const openReasoning = document.querySelector("details.model-menu[open] .model-option:hover, details.model-menu[open] .model-option.reasoning-open");
	      if (openReasoning) {
	        const modelMenu = openReasoning.closest("details.model-menu");
	        openReasoningProfile = modelMenu ? modelMenu.dataset.profile || null : null;
	        openReasoningModel = openReasoning.dataset.model || null;
	      }
	    }

	    function restoreMenu(selector, profile) {
	      if (!profile) return;
	      document.querySelectorAll(selector).forEach((menu) => {
	        menu.open = menu.dataset.profile === profile;
	      });
	    }

	    function restoreOpenMenus() {
	      restoreMenu("details.pin-menu", openPinMenuProfile);
	      restoreMenu("details.model-menu", openModelMenuProfile);
	      restoreMenu("details.login-menu", openLoginMenuProfile);
	      restoreReasoningMenu();
	    }

	    function restoreReasoningMenu() {
	      document.querySelectorAll(".model-option.reasoning-open").forEach((option) => {
	        option.classList.remove("reasoning-open");
	      });
	      if (!openReasoningProfile || !openReasoningModel) return;
	      const menu = Array.from(document.querySelectorAll("details.model-menu"))
	        .find((item) => item.dataset.profile === openReasoningProfile);
	      const option = menu
	        ? Array.from(menu.querySelectorAll(".model-option")).find((item) => item.dataset.model === openReasoningModel)
	        : null;
	      if (option) option.classList.add("reasoning-open");
	    }

	    function closeMenus(selector) {
	      document.querySelectorAll(`${selector}[open]`).forEach((menu) => {
	        menu.open = false;
	      });
	    }

	    function closeOpenMenus() {
	      openPinMenuProfile = null;
	      openModelMenuProfile = null;
	      openLoginMenuProfile = null;
	      openReasoningProfile = null;
	      openReasoningModel = null;
	      closeMenus("details.pin-menu");
	      closeMenus("details.model-menu");
	      closeMenus("details.login-menu");
	    }

	    function menuType(menu) {
	      if (menu.classList.contains("pin-menu")) return "pin";
	      if (menu.classList.contains("model-menu")) return "model";
	      if (menu.classList.contains("login-menu")) return "login";
	      return "";
	    }

	    function menuSelector(type) {
	      if (type === "pin") return "details.pin-menu";
	      if (type === "model") return "details.model-menu";
	      if (type === "login") return "details.login-menu";
	      return "";
	    }

	    function setOpenMenuProfile(type, profile) {
	      if (type === "pin") openPinMenuProfile = profile;
	      if (type === "model") openModelMenuProfile = profile;
	      if (type === "login") openLoginMenuProfile = profile;
	    }

	    function getOpenMenuProfile(type) {
	      if (type === "pin") return openPinMenuProfile;
	      if (type === "model") return openModelMenuProfile;
	      if (type === "login") return openLoginMenuProfile;
	      return null;
	    }

		    function updateQuotaRefreshEpoch(status) {
		      const pid = status ? status.pid || null : null;
		      if (!pid || pid === quotaRefreshDaemonPid) return;
		      if (pageDaemonPid && pid !== pageDaemonPid) {
		        window.location.reload();
		        return;
		      }
		      quotaRefreshDaemonPid = pid;
	      quotaRefreshAttempted.clear();
	      quotaRefreshQueue.length = 0;
	      quotaRefreshInFlight = "";
	      if (quotaRefreshTimer) {
	        clearTimeout(quotaRefreshTimer);
	        quotaRefreshTimer = null;
	      }
	    }

	    function queueInitialQuotaRefreshes(profiles) {
	      for (const profile of profiles || []) {
	        const name = String(profile.name || "");
	        const billingRequired = profile.billing_required && typeof profile.billing_required === "object" && profile.billing_required.required;
	        if (!name || profile.quota_has_payload || profile.quota_refresh_error || billingRequired) continue;
	        if (quotaRefreshAttempted.has(name)) continue;
	        quotaRefreshAttempted.add(name);
	        quotaRefreshQueue.push(name);
	      }
	    }

	    function scheduleNextQuotaRefresh(delay = 0) {
	      if (quotaRefreshTimer || quotaRefreshInFlight) return;
	      quotaRefreshTimer = setTimeout(() => {
	        quotaRefreshTimer = null;
	        if (!socket || socket.readyState !== WebSocket.OPEN || quotaRefreshInFlight) return;
	        while (quotaRefreshQueue.length) {
	          const profile = quotaRefreshQueue.shift();
	          if (!profile) continue;
	          quotaRefreshInFlight = profile;
	          socket.send(JSON.stringify({
	            action: "refresh_quota",
	            profile,
	          }));
	          return;
	        }
	      }, delay);
	    }

		    function reasoningDisplay(value) {
		      return String(value || "");
		    }

		    function profileStateFromValue(value) {
		      if (!value) return null;
		      if (typeof value === "string") {
		        const raw = value.trim();
		        if (raw === "deactivated_workspace") {
		          return { code: raw, title: "Workspace deactivated", message: "This workspace is deactivated." };
		        }
		        if (raw.startsWith("{") && raw.endsWith("}")) {
		          try {
		            return profileStateFromValue(JSON.parse(raw));
		          } catch {
		            return null;
		          }
		        }
		        return null;
		      }
		      if (typeof value !== "object") return null;
		      const code = typeof value.code === "string" ? value.code : "";
		      if (code === "deactivated_workspace") {
		        return { code, title: "Workspace deactivated", message: "This workspace is deactivated." };
		      }
		      return profileStateFromValue(value.detail) || profileStateFromValue(value.error) || profileStateFromValue(value.message) || profileStateFromValue(value.reason);
		    }

	    function renderAuthHealth(profile) {
	      if (profile.auth_health_html) return profile.auth_health_html;
	      const health = profile.auth_health && typeof profile.auth_health === "object" ? profile.auth_health : null;
	      if (!health) return "";
	      const status = String(health.status || "");
	      if (status !== "login_required" && status !== "refresh_failed") return "";
	      const label = status === "login_required" ? "Login required" : "Auth refresh failed";
	      const timestamp = formatEventTime(health.error_at || health.last_refresh_failed_at || "");
	      const suffix = timestamp ? ` (${timestamp})` : "";
	      return `
	        <div class="auth-health ${escapeHtml(status)}" title="${escapeHtml(health.message || "")}">
	          <strong>${escapeHtml(label)}</strong>${escapeHtml(suffix)}
	        </div>
	      `;
	    }

	    function renderQuotaRefreshControl(profileName) {
	      if (!profileName) return '<span class="quota-refresh-spacer"></span>';
	      return `
	        <form method="post" action="/api/refresh-quota" class="quota-refresh-form" data-action="refresh_quota" data-profile="${escapeHtml(profileName)}">
	          <input type="hidden" name="profile" value="${escapeHtml(profileName)}">
	          <button class="quota-refresh-icon" aria-label="Refresh quota" title="Refresh quota">
	            <svg class="quota-refresh-glyph" viewBox="0 0 24 24" fill="none" aria-hidden="true">
	              <path d="M20 12a8 8 0 1 1-2.34-5.66"></path>
	              <path d="M20 4v5h-5"></path>
	            </svg>
	          </button>
	        </form>
	      `;
	    }

	    function renderQuotaCredits(label) {
	      return label
	        ? `<span class="quota-credits-pill" title="Codex credits balance">Credits: ${escapeHtml(label)}</span>`
	        : "";
	    }

	    function renderResetCreditControl(resetCredit, profileName) {
	      if (!resetCredit || typeof resetCredit !== "object") return "";
	      const label = String(resetCredit.label || "");
	      if (!label) return "";
	      const message = String(resetCredit.message || "");
	      if (resetCredit.disabled) {
	        return `<span class="quota-reset-credit-pill disabled" title="${escapeHtml(message)}">${escapeHtml(label)}</span>`;
	      }
	      const credits = usableResetCredits(resetCredit.credits);
	      return `
	        <form method="post" action="/api/consume-reset-credit" class="reset-credit-form" data-action="consume_reset_credit" data-profile="${escapeHtml(profileName)}" data-reset-credits="${escapeHtml(JSON.stringify(credits))}">
	          <input type="hidden" name="profile" value="${escapeHtml(profileName)}">
	          <input type="hidden" name="credit_id" value="">
	          <button class="quota-reset-credit-pill" title="Choose a reset credit to use">${escapeHtml(label)}</button>
	        </form>
	      `;
	    }

	    function renderQuotaState(state) {
	      const data = state && typeof state === "object" ? state : {};
	      const level = ["warning", "error", "info"].includes(String(data.level || "")) ? String(data.level) : "warning";
	      const title = String(data.title || "Quota unavailable");
	      const message = String(data.message || "Quota is unavailable for this profile.");
	      return `
	        <div class="quota-empty quota-state ${escapeHtml(level)}">
	          <strong>${escapeHtml(title)}</strong>
	          <span>${escapeHtml(message)}</span>
	        </div>
	      `;
	    }

	    function renderQuotaCountRows(rows) {
	      return (rows || []).map((row) => {
	        const reset = row.reset ? ` <span class="quota-count-reset">(${escapeHtml(row.reset)})</span>` : "";
	        return `<div class="quota-count-line"><span>${escapeHtml(row.label || "")}</span><strong>${escapeHtml(row.value || "")}</strong>${reset}</div>`;
	      }).join("") || '<div class="quota-muted">No window details</div>';
	    }

	    function renderQuotaHorizons(stack, bucket) {
	      const name = String(bucket.name || "Quota bucket");
	      const title = String(bucket.title || "");
	      const special = String(stack.special || "");
	      const specialClass = special ? ` ${special}` : "";
	      if (Array.isArray(stack.count_rows) && stack.count_rows.length) {
	        return `
	          <div class="quota-title${escapeHtml(specialClass)}">
	            <span class="quota-horizon weekly"></span>
	            <span class="quota-bucket-name" title="${escapeHtml(title)}">${escapeHtml(name)}</span>
	            <span class="quota-horizon primary"></span>
	          </div>
	        `;
	      }
	      const primaryNotEnforced = Boolean(stack.primary_not_enforced);
	      const primaryClass = primaryNotEnforced ? "primary not-enforced" : "primary";
	      return `
	        <div class="quota-title${escapeHtml(specialClass)}">
	          <span class="quota-horizon weekly">${escapeHtml(stack.weekly_status || "")}</span>
	          <span class="quota-bucket-name" title="${escapeHtml(title)}">${escapeHtml(name)}</span>
	          <span class="quota-horizon ${primaryClass}">${escapeHtml(stack.primary_reset_text || "")}</span>
	        </div>
	      `;
	    }

	    function renderQuotaStack(stack) {
	      if (Array.isArray(stack.count_rows) && stack.count_rows.length) {
	        return renderQuotaCountRows(stack.count_rows);
	      }
	      const primaryStyle = Number(stack.primary_style || 0);
	      const weeklyStyle = Number(stack.weekly_style || 0);
	      const primaryText = String(stack.primary_text || "");
	      const weeklyText = String(stack.weekly_text || "");
	      const primaryEmpty = String(stack.primary_empty || "");
	      const primaryNotEnforced = Boolean(stack.primary_not_enforced);
	      const special = String(stack.special || "");
	      const stackClass = `${special ? ` quota-stack-${special}` : ""}${primaryNotEnforced ? " quota-stack-primary-not-enforced" : ""}`;
	      const aria = String(stack.aria || "");
	      const barAttrs = special || primaryNotEnforced
	        ? `role="img" aria-label="${escapeHtml(aria)}"`
	        : `role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${primaryStyle.toFixed(0)}" aria-label="${escapeHtml(aria)}"`;
	      const primaryLabelClass = primaryNotEnforced ? "quota-primary-label-outside not-enforced" : "quota-primary-label-outside";
	      return `
	        <div class="quota-stack${escapeHtml(stackClass)}">
	          <div class="quota-stack-row">
	            <span class="quota-weekly-label">${escapeHtml(weeklyText)}</span>
	            <div class="quota-stack-bar" ${barAttrs}>
	              <span class="quota-weekly-fill" style="width: ${weeklyStyle.toFixed(2)}%"></span>
	              <span class="quota-primary-fill${escapeHtml(primaryEmpty)}" style="width: ${primaryStyle.toFixed(2)}%"></span>
	            </div>
	            <span class="${primaryLabelClass}">${escapeHtml(primaryText)}</span>
	          </div>
	        </div>
	      `;
	    }

	    function renderQuotaBucket(bucket) {
	      const stack = bucket && typeof bucket.stack === "object" ? bucket.stack : {};
	      return `
	        <div class="quota-bucket">
	          ${renderQuotaHorizons(stack, bucket || {})}
	          ${renderQuotaStack(stack)}
	        </div>
	      `;
	    }

	    function renderStructuredQuota(profile, profileName) {
	      const quota = profile.quota && typeof profile.quota === "object" ? profile.quota : null;
	      if (!quota) return profile.quota_html || '<div class="quota-empty">No quota cached</div>';
	      const updated = String(quota.updated || "No quota cached");
	      let body = "";
	      const buckets = Array.isArray(quota.buckets) ? quota.buckets : [];
	      if (buckets.length) {
	        body = buckets.map((bucket) => renderQuotaBucket(bucket)).join("");
	      } else if (quota.state) {
	        body = renderQuotaState(quota.state);
	      } else {
	        const empty = String(quota.empty || "No quota cached");
	        const emptyClass = quota.refresh_error_billing ? "quota-empty error billing" : empty === "Quota payload has no bucket details" ? "quota-muted" : "quota-empty";
	        body = `<div class="${emptyClass}">${escapeHtml(empty)}</div>`;
	      }
	      const refreshError = quota.refresh_error
	        ? `<div class="quota-refresh-error${quota.refresh_error_billing ? " billing" : ""}">Last refresh failed: ${escapeHtml(quota.refresh_error)}</div>`
	        : "";
	      return `
	        <div class="quota-panel">
	          <div class="quota-panel-head">
	            ${renderQuotaRefreshControl(profileName)}
	            <span class="quota-updated">${escapeHtml(updated)}</span>
	            ${renderResetCreditControl(quota.reset_credit, profileName)}
	            ${renderQuotaCredits(quota.credits_label)}
	          </div>
	          ${body}
	          ${refreshError}
	        </div>
	      `;
	    }

	    function modelCatalog(profile) {
	      const profileCatalog = profile && Array.isArray(profile.model_catalog) ? profile.model_catalog : [];
	      return profileCatalog.length ? profileCatalog : (latestModelCatalog.length ? latestModelCatalog : [
	        { id: "gpt-5.6-sol", display: "GPT-5.6-Sol", reasoning: ["low", "medium", "high", "xhigh", "max", "ultra"] },
		        { id: "gpt-5.6-terra", display: "GPT-5.6-Terra", reasoning: ["low", "medium", "high", "xhigh", "max", "ultra"] },
		        { id: "gpt-5.6-luna", display: "GPT-5.6-Luna", reasoning: ["low", "medium", "high", "xhigh", "max"] },
		        { id: "gpt-5.5", display: "GPT-5.5", reasoning: ["low", "medium", "high", "xhigh"] },
		        { id: "gpt-5.4", display: "GPT-5.4", reasoning: ["low", "medium", "high", "xhigh"] },
		        { id: "gpt-5.4-mini", display: "GPT-5.4-Mini", reasoning: ["low", "medium", "high", "xhigh"] },
	        { id: "gpt-5.2", display: "GPT-5.2", reasoning: ["low", "medium", "high", "xhigh"] }
	      ]);
	    }

	    function stableRenderHash(value) {
	      let hash = 2166136261;
	      const text = String(value || "");
	      for (let index = 0; index < text.length; index += 1) {
	        hash ^= text.charCodeAt(index);
	        hash = Math.imul(hash, 16777619);
	      }
	      return String(hash >>> 0);
	    }

		    function renderProfileChips(profile, name) {
		      const chips = [];
		      if (profile.active) chips.push('<span class="badge active-badge">Active</span>');
			      const billingRequired = profile.billing_required && typeof profile.billing_required === "object" && profile.billing_required.required;
			      if (billingRequired) {
			        const detail = String(profile.billing_required.error || "This Codex CLI profile returned HTTP 402 Payment Required.");
			        const state = profileStateFromValue(profile.billing_required.error);
			        const title = state ? state.message : `Billing required: Provision has paused automatic quota refreshes for this profile. ${detail}`;
			        const label = state ? state.title : "Billing required";
			        chips.push(`<span class="profile-pill billing-pill" title="${escapeHtml(title)}">${escapeHtml(label)}</span>`);
			      }
		      const fastEnabled = Boolean(profile.fast_mode);
	      chips.push(`
	        <form method="post" action="/api/toggle-fast" class="profile-pill-form" data-action="toggle_fast" data-profile="${escapeHtml(name)}">
	          <input type="hidden" name="profile" value="${escapeHtml(name)}">
	          <button class="profile-pill fast-pill${fastEnabled ? " enabled" : ""}" title="Toggle fast mode">Fast</button>
	        </form>
	      `);
	      const loginRequired = profile.login_required && typeof profile.login_required === "object" && profile.login_required.required;
	      const loginStatus = profile.login_status && typeof profile.login_status === "object" ? profile.login_status : null;
	      const loginState = loginStatus ? String(loginStatus.status || "") : "";
	      const loginRunning = loginState === "running" || loginState === "canceling";
	      if (loginRequired || loginRunning) {
	        const loginTitle = loginRunning ? "Login already running" : String((profile.login_required && profile.login_required.error) || "Refresh profile login");
	        const disabled = loginRunning ? "disabled" : "";
	        const cancelDisabled = loginState === "canceling" ? "disabled" : "";
	        const cancelForm = loginRunning ? `
	          <form method="post" action="/api/login" data-action="cancel_login" data-profile="${escapeHtml(name)}">
	            <input type="hidden" name="profile" value="${escapeHtml(name)}">
	            <input type="hidden" name="login_action" value="cancel_login">
	            <button class="menu-action danger-action" ${cancelDisabled}>Cancel Login</button>
	          </form>
	        ` : "";
	        chips.push(`
	          <details class="login-menu profile-login-menu" data-profile="${escapeHtml(name)}">
	            <summary class="profile-pill login-pill" title="${escapeHtml(loginTitle)}">Login</summary>
	            <div class="login-menu-panel">
	              <div class="login-menu-note">${escapeHtml(LOGIN_BROWSER_REMOTE_NOTE)}</div>
	              <form method="post" action="/api/login" data-action="start_login" data-profile="${escapeHtml(name)}">
	                <input type="hidden" name="profile" value="${escapeHtml(name)}">
	                <input type="hidden" name="mode" value="browser">
	                <button class="menu-action" ${disabled}>Browser Login</button>
	              </form>
	              <form method="post" action="/api/login" data-action="start_login" data-profile="${escapeHtml(name)}">
	                <input type="hidden" name="profile" value="${escapeHtml(name)}">
	                <input type="hidden" name="mode" value="device">
	                <button class="menu-action" ${disabled}>Device Auth</button>
	              </form>
	              ${cancelForm}
	            </div>
	          </details>
	        `);
	      }
	      return `<div class="profile-chips">${chips.join("")}</div>`;
	    }

		    function renderModelMenu(profile, name) {
		      const setting = profile.model_setting && typeof profile.model_setting === "object" ? profile.model_setting : {};
		      const currentModel = String(setting.model || "gpt-5.6-sol");
		      const currentReasoning = String(setting.reasoning_effort || (currentModel === "gpt-5.6-sol" ? "low" : "medium"));
			      const label = `${currentModel.toLowerCase()} ${reasoningDisplay(currentReasoning)}`;
	      const items = modelCatalog(profile).map((item) => {
	        const model = String(item.id || "");
	        if (!model) return "";
	        const display = String(item.display || model);
	        const note = String(item.note || "");
	        const selected = model === currentModel ? " selected" : "";
		        const levels = Array.isArray(item.reasoning) && item.reasoning.length ? item.reasoning : ["none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"];
	        const reasoning = levels.map((level) => {
	          const value = String(level || "");
	          if (!value) return "";
	          const reasoningSelected = model === currentModel && value === currentReasoning ? " selected" : "";
	          return `
	            <form method="post" action="/api/model" data-action="set_model" data-profile="${escapeHtml(name)}">
	              <input type="hidden" name="profile" value="${escapeHtml(name)}">
	              <input type="hidden" name="model" value="${escapeHtml(model)}">
	              <input type="hidden" name="reasoning_effort" value="${escapeHtml(value)}">
	              <button class="model-reasoning-option${reasoningSelected}">${escapeHtml(reasoningDisplay(value))}</button>
	            </form>
	          `;
	        }).join("");
	        return `
	          <div class="model-option${selected}" data-model="${escapeHtml(model)}" title="${escapeHtml(note)}">
	            <button class="model-option-label" type="button">
	              <span>${escapeHtml(display)}</span>
	              <span class="model-option-arrow">&rsaquo;</span>
	            </button>
	            <div class="model-reasoning-menu">${reasoning}</div>
	          </div>
	        `;
	      }).join("");
	      return `
	        <details class="model-menu" data-profile="${escapeHtml(name)}">
	          <summary class="model-pill" title="Select model and reasoning effort">
	            <span>${escapeHtml(label)}</span>
	          </summary>
	          <div class="model-menu-panel">${items}</div>
	        </details>
	      `;
	    }

	    function profileRow(profile, pendingAction, pendingProfile) {
	      const name = String(profile.name || "");
	      const plan = String(profile.plan_type || "unknown");
	      const hidden = Boolean(profile.hidden);
	      const reason = String(profile.switch_disabled_reason || "");
	      const pending = pendingProfile === name ? pendingAction : "";
	      const disabled = reason || pending ? "disabled" : "";
	      const useTitle = reason || (pending ? "Action in progress" : "");
	      const useLabel = pending === "switch" ? "Switching" : String(profile.switch_button_label || "Use");
	      let useClass = profile.active ? "primary-action current-action" : "primary-action";
	      if (profile.active && profile.has_active_sessions) useClass += " session-active-action";
	      const quotaPendingLabel = pending === "consume_reset_credit" ? "Using reset credit" : "Refreshing quota";
	      const isQuotaPending = pending === "refresh_quota" || pending === "consume_reset_credit";
	      const quota = isQuotaPending
	        ? `<div class="quota-panel"><div class="quota-panel-head"><span class="quota-refresh-icon disabled" aria-hidden="true"><span class="spinner quota-spinner-small"></span></span><span class="quota-updated">${quotaPendingLabel}</span></div><div class="quota-loading"><span class="spinner"></span><span>${quotaPendingLabel}</span></div></div>`
	        : renderStructuredQuota(profile, name);
	      const pinMenu = profile.pin_menu_html || "";
	      const pinnedSessions = profile.pinned_sessions_html || "";
	      const loginStatusHtml = profile.login_status_html || "";
	      const authHealthHtml = renderAuthHealth(profile);
	      return `
	        <tr class="profile-row${profile.active ? " active" : ""}${hidden ? " hidden-profile" : ""}" data-profile="${escapeHtml(name)}" data-profile-key="${escapeHtml(name)}">
	          <td class="profile-cell">
	            <div class="profile-name">${escapeHtml(name)} <span class="profile-plan">(${escapeHtml(plan)})</span>${hidden ? ' <span class="profile-hidden-badge">Hidden</span>' : ""}</div>
	            <div class="profile-email">${escapeHtml(profile.email || profile.account_id || "")}</div>
	            ${authHealthHtml}
	            ${renderProfileChips(profile, name)}
	            ${pinMenu}
	            ${pinnedSessions}
	            ${loginStatusHtml}
	          </td>
	          <td class="model-cell">${renderModelMenu(profile, name)}</td>
	          <td class="quota-cell">${quota}</td>
	          <td class="actions">
	            <form method="post" action="/api/switch" data-action="switch" data-profile="${escapeHtml(name)}">
	              <input type="hidden" name="profile" value="${escapeHtml(name)}">
	              <button class="${useClass}" ${disabled} title="${escapeHtml(useTitle)}">${escapeHtml(useLabel)}</button>
	            </form>
	            <form method="post" action="/api/profile-visibility" data-action="set_profile_visibility" data-profile="${escapeHtml(name)}">
	              <input type="hidden" name="profile" value="${escapeHtml(name)}">
	              <input type="hidden" name="hidden" value="${hidden ? "false" : "true"}">
	              <button class="profile-visibility-action" title="${hidden ? "Show this profile in the dashboard" : "Hide this profile from the dashboard"}">${hidden ? "Unhide" : "Hide"}</button>
	            </form>
	          </td>
	        </tr>
	      `;
	    }

	    function providerProfileRow(profile) {
	      const provider = String(profile.provider || "provider");
	      const providerLabel = String(profile.provider_label || (provider ? provider.charAt(0).toUpperCase() + provider.slice(1) : "Provider"));
	      const displayName = String(profile.display_name || profile.name || "Native");
	      const key = String(profile.key || `provider:${provider}:${displayName}`);
	      const models = Array.isArray(profile.models) ? profile.models.filter(Boolean) : [];
	      const modelHtml = models.length
	        ? models.map((model) => `<span class="model-pill provider-model-pill">${escapeHtml(model)}</span>`).join("")
	        : '<span class="quota-muted">Observed model unavailable</span>';
	      const usage = profile.usage && typeof profile.usage === "object" ? profile.usage : {};
	      const usageRows = [
	        ["Total tokens", "totalTokens"],
	        ["Input", "inputTokens"],
	        ["Output", "outputTokens"],
	        ["Reasoning", "reasoningTokens"],
	        ["Cached read", "cachedReadTokens"],
	        ["Cache write", "cacheCreationTokens"],
	        ["Model calls", "modelCalls"],
	        ["Agent turns", "numTurns"]
	      ].filter(([, field]) => Number.isFinite(Number(usage[field])))
	        .map(([label, field]) => `<span><span>${escapeHtml(label)}</span><strong>${escapeHtml(formatNumber(Number(usage[field])))}</strong></span>`);
	      if (Number.isFinite(Number(usage.costUsdTicks))) {
	        const cost = Number(usage.costUsdTicks) / 10000000000;
	        const costText = cost.toFixed(4).replace(/0+$/, "").replace(/\.$/, "") || "0";
	        usageRows.push(`<span><span>Server-reported cost</span><strong>$${escapeHtml(costText)}</strong></span>`);
	      }
	      const usageHtml = usageRows.length
	        ? `<div class="provider-usage-head">Latest observed turn</div><div class="provider-usage-grid">${usageRows.join("")}</div>`
	        : `<div class="quota-muted">${escapeHtml(profile.usage_empty || "No completed-turn usage observed yet.")}</div>`;
	      const quota = profile.quota && typeof profile.quota === "object" ? profile.quota : {};
	      const defaultBadge = profile.default_provider
	        ? '<span class="badge active-badge">Default provider identity</span>'
	        : (profile.selected_for_provider ? `<span class="profile-pill provider-default-pill">${escapeHtml(profile.selection_label || `${providerLabel} default`)}</span>` : "");
	      const accountLabel = String(profile.account_label || "");
	      const accountHtml = accountLabel ? `<div class="profile-email">${escapeHtml(accountLabel)}</div>` : "";
	      const profileKind = String(profile.profile_kind_label || (profile.managed ? "Managed provider profile" : "Provider native"));
	      const authStatus = String(profile.auth_status || "");
	      const authStatusHtml = authStatus
	        ? `<span class="profile-pill${profile.logged_in === false ? " login-pill" : ""}">${escapeHtml(authStatus)}</span>`
	        : "";
	      const subscription = String(profile.subscription_label || "");
	      const subscriptionHtml = subscription
	        ? `<span class="profile-pill">${escapeHtml(subscription)}</span>`
	        : "";
	      const sessionCount = Number(profile.session_count || 0);
	      const activeCount = Number(profile.active_session_count || 0);
	      let sessionLabel = `${formatNumber(sessionCount)} session${sessionCount === 1 ? "" : "s"}`;
	      if (activeCount) sessionLabel += ` / ${formatNumber(activeCount)} active`;
	      return `
	        <tr class="profile-row provider-profile-row${profile.default_provider ? " active" : ""}" data-profile-key="${escapeHtml(key)}">
	          <td class="profile-cell">
	            <div class="profile-name">${escapeHtml(providerLabel)} <span class="profile-plan">(${escapeHtml(displayName)})</span></div>
	            <div class="profile-email">${escapeHtml(profile.identity_label || "Native provider identity")}</div>
	            ${accountHtml}
	            <div class="profile-chips"><span class="profile-pill provider-pill">${escapeHtml(profileKind)}</span>${authStatusHtml}${subscriptionHtml}${defaultBadge}</div>
	          </td>
	          <td class="model-cell"><div class="provider-models">${modelHtml}</div></td>
	          <td class="quota-cell">
	            <div class="provider-quota-panel">
	              <div class="provider-quota-head"><span>Account quota</span><strong>${escapeHtml(quota.status || "Account quota unavailable")}</strong></div>
	              <div class="provider-quota-detail">${escapeHtml(quota.detail || "")}</div>
	              ${usageHtml}
	            </div>
	          </td>
	          <td class="actions provider-actions"><span>${escapeHtml(sessionLabel)}</span></td>
	        </tr>
	      `;
	    }

	    function renderProfileRows(profiles, providerProfiles, pendingAction, pendingProfile) {
	      const body = document.getElementById("profileRows");
	      if (!body) return;
	      const allProfiles = Array.isArray(profiles) ? profiles : [];
	      const allProviderProfiles = Array.isArray(providerProfiles) ? providerProfiles : [];
	      const hiddenCount = allProfiles.filter((profile) => Boolean(profile && profile.hidden)).length;
	      const toggle = document.getElementById("profileHiddenToggle");
	      if (toggle) {
	        toggle.hidden = hiddenCount === 0;
	        toggle.textContent = showHiddenProfiles
	          ? `Hide hidden profiles (${hiddenCount})`
	          : `Show hidden profiles (${hiddenCount})`;
	        toggle.setAttribute("aria-pressed", showHiddenProfiles ? "true" : "false");
	      }
	      const visibleProfiles = showHiddenProfiles
	        ? allProfiles
	        : allProfiles.filter((profile) => !Boolean(profile && profile.hidden));
	      const existing = new Map();
	      Array.from(body.children).forEach((row) => {
	        if (row instanceof HTMLElement) existing.set(row.dataset.profileKey || "", row);
	      });
	      const seen = new Set();
	      const template = document.createElement("template");
	      const rows = visibleProfiles.map((profile, index) => ({
	        key: String(profile && profile.name || `profile-${index}`),
	        html: profileRow(profile, pendingAction, pendingProfile).trim()
	      })).concat(allProviderProfiles.map((profile, index) => ({
	        key: String(profile && profile.key || `provider-profile-${index}`),
	        html: providerProfileRow(profile || {}).trim()
	      })));
	      for (const item of rows) {
	        const name = item.key;
	        const html = item.html;
	        const hash = stableRenderHash(html);
	        let row = existing.get(name);
	        if (!row || row.dataset.renderHash !== hash) {
	          template.innerHTML = html;
	          const next = template.content.firstElementChild;
	          if (!(next instanceof HTMLElement)) continue;
	          next.dataset.profileKey = name;
	          next.dataset.renderHash = hash;
	          if (row) {
	            row.replaceWith(next);
	          } else {
	            body.appendChild(next);
	          }
	          row = next;
	          normalizeNativeTooltips(row);
	        }
	        seen.add(name);
	        body.appendChild(row);
	      }
	      for (const [key, row] of existing.entries()) {
	        if (!seen.has(key)) row.remove();
	      }
	    }

    function render(packet) {
      const status = packet.status || {};
      latestStatus = status;
      const sections = new Set(Array.isArray(packet.sections) ? packet.sections : ["full"]);
      const fullRender = sections.has("full") || !Array.isArray(packet.sections);
      const profilesChanged = fullRender || sections.has("profiles");
      const controlChanged = fullRender || sections.has("control_plane");
      const statsChanged = fullRender || sections.has("stats");
      const permissionsChanged = fullRender || sections.has("permissions");
      updateQuotaRefreshEpoch(status);
      const pendingAction = packet.pending_action || "";
      const pendingProfile = String(packet.pending_profile || "");
      const activeRequests = Number(status.active_requests || 0);
      const activeTunnels = Number(status.active_websockets || 0);
      const liveBusy = Boolean(status.live_busy);
      latestLiveBusy = liveBusy;
      latestStats = status.stats || latestStats || { profiles: [], recent: [] };
      latestControlPlane = status.control_plane || latestControlPlane || { sessions: [] };
      latestCodex = status.codex || latestCodex || {};
      latestPermissions = status.permissions || latestPermissions || { pending: [] };
      if (Array.isArray(status.model_catalog)) latestModelCatalog = status.model_catalog;
	      if ((pendingAction === "refresh_quota" || pendingAction === "consume_reset_credit") && pendingProfile) {
	        quotaRefreshInFlight = pendingProfile;
	      } else if (quotaRefreshInFlight) {
	        quotaRefreshInFlight = "";
	        scheduleNextQuotaRefresh(250);
	      }
	      if (profilesChanged) queueInitialQuotaRefreshes(status.profiles || []);
	      scheduleNextQuotaRefresh(250);
	      document.getElementById("activeProfile").textContent = status.active_profile || "none";
	      document.getElementById("defaultProvider").textContent = status.default_provider || "codex";
	      const codexRuntimeCli = status.codex && status.codex.runtime_cli ? status.codex.runtime_cli : {};
	      const codexStartupCli = status.codex && status.codex.cli ? status.codex.cli : {};
	      const codexCli = codexRuntimeCli.version ? codexRuntimeCli : codexStartupCli;
	      document.getElementById("codexVersion").textContent = codexCli.version || "unknown";
	      const restartState = status.codex && status.codex.restart_required ? status.codex.restart_required : {};
	      const restartRequired = Boolean(restartState.required);
	      const restartNotice = document.getElementById("codexRestartRequired");
	      restartNotice.hidden = !restartRequired;
	      restartNotice.title = restartRequired ? String(restartState.reason || "Restart Provision when active work is idle.") : "";
	      document.getElementById("activeRequests").textContent = String(activeRequests);
	      document.getElementById("activeTunnels").textContent = String(activeTunnels);
	      if (controlChanged) {
	        renderSessionTabs(status);
	        renderLauncherBar(status);
	      }
	      const connection = document.getElementById("connectionState");
	      const isDisconnected = connection.textContent === "Disconnected";
	      if (!isDisconnected) {
	        connection.textContent = `Live (${liveBusy ? "busy" : "idle"})`;
	        document.getElementById("proxyDot").className = "dot" + (liveBusy ? " busy" : "");
	      }
	      if (profilesChanged) {
	        rememberOpenMenus();
	        renderProfileRows(
	          status.profiles || [],
	          status.provider_profiles || [],
	          pendingAction,
	          pendingProfile
	        );
	        restoreOpenMenus();
	      }
	      if (statsChanged && !document.getElementById("statsModal").hidden) {
	        renderStats(latestStats);
      }
	      if (controlChanged) renderControlModal();
	      if (permissionsChanged || controlChanged) renderPermissionModal();
	      if (fullRender || profilesChanged || controlChanged || statsChanged || permissionsChanged) normalizeNativeTooltips(document);
	      if (typeof packet.message === "string") {
	        showUiMessage(packet.message);
	      }
    }

	    function mergeStateDelta(packet) {
	      const delta = packet.status || {};
	      const previous = latestStatus || {};
	      const merged = {
	        ...previous,
	        ...delta,
	        profiles: Object.prototype.hasOwnProperty.call(delta, "profiles")
	          ? delta.profiles
	          : (previous.profiles || []),
	        provider_profiles: Object.prototype.hasOwnProperty.call(delta, "provider_profiles")
	          ? delta.provider_profiles
	          : (previous.provider_profiles || []),
	        sessions: Object.prototype.hasOwnProperty.call(delta, "sessions")
	          ? delta.sessions
	          : (previous.sessions || []),
	        control_plane: Object.prototype.hasOwnProperty.call(delta, "control_plane")
	          ? delta.control_plane
	          : (previous.control_plane || latestControlPlane || { sessions: [] }),
	        stats: Object.prototype.hasOwnProperty.call(delta, "stats")
	          ? delta.stats
	          : (previous.stats || latestStats || { profiles: [], recent: [] }),
	        codex: Object.prototype.hasOwnProperty.call(delta, "codex")
	          ? delta.codex
	          : (previous.codex || latestCodex || {}),
	        permissions: Object.prototype.hasOwnProperty.call(delta, "permissions")
	          ? delta.permissions
	          : (previous.permissions || latestPermissions || { pending: [] }),
	        model_catalog: Object.prototype.hasOwnProperty.call(delta, "model_catalog")
	          ? delta.model_catalog
	          : (previous.model_catalog || latestModelCatalog || [])
	      };
	      latestStatus = merged;
	      return { ...packet, type: "state", status: merged };
	    }

	    function scheduleRender(packet) {
	      const statePacket = packet.type === "state_delta" ? mergeStateDelta(packet) : packet;
	      if (packet.type === "state") latestStatus = packet.status || {};
	      pendingRenderPacket = statePacket;
	      if (pendingRenderFrame) return;
	      pendingRenderFrame = requestAnimationFrame(() => {
	        const nextPacket = pendingRenderPacket;
	        pendingRenderPacket = null;
	        pendingRenderFrame = null;
	        if (nextPacket) render(nextPacket);
	      });
	    }

	    function handleHistoryTurnPacket(packet) {
	      const sessionKey = String(packet.session_key || "");
	      const turnKey = String(packet.turn_key || "");
	      const key = historyCacheKey(sessionKey, turnKey);
	      delete historyTurnRequests[key];
	      if (!packet.ok) {
	        showUiMessage(packet.error ? `History load failed: ${packet.error}` : "History load failed.");
	        return;
	      }
	      if (packet.payload && typeof packet.payload === "object") {
	        historyTurnCache[key] = packet.payload;
	      }
	      if (sessionKey === selectedControlSessionKey && selectedControlTurnKeys[sessionKey] === turnKey) {
	        renderControlModal(true);
	      }
	    }

	    function handleObservedTurnPacket(packet) {
	      const sessionKey = String(packet.session_key || "");
	      const turnKey = String(packet.turn_key || "");
	      const cacheKey = historyCacheKey(sessionKey, turnKey);
	      for (const key of Object.keys(observedTurnRequests)) {
	        if (key.startsWith(`${cacheKey}\u0001`)) delete observedTurnRequests[key];
	      }
	      if (!packet.ok) {
	        showUiMessage(packet.error ? `Discussion load failed: ${packet.error}` : "Discussion load failed.");
	        return;
	      }
	      if (packet.payload && typeof packet.payload === "object" && Array.isArray(packet.payload.transcript)) {
	        const incoming = packet.payload;
	        const existing = observedTurnCache[cacheKey];
	        observedTurnCache[cacheKey] = mergeObservedTurnPayload(existing, incoming);
	      }
	      if (sessionKey === selectedControlSessionKey) renderControlModal(true);
	    }

	    function handleTerminalSnapshotPacket(packet) {
	      const sessionKey = String(packet.session_key || "");
	      if (!packet.ok) {
	        showUiMessage(packet.error ? `Terminal snapshot failed: ${packet.error}` : "Terminal snapshot failed.");
	        return;
	      }
	      if (packet.snapshot && typeof packet.snapshot === "object") {
	        terminalSnapshotCache[sessionKey] = packet.snapshot;
	      }
	      if (sessionKey === selectedControlSessionKey && controlView === "terminal") renderControlModal(true);
	    }

	    function handleHistoryIndexPacket(packet) {
	      const sessionKey = String(packet.session_key || "");
	      delete historyIndexRequests[sessionKey];
	      if (!packet.ok) {
	        showUiMessage(packet.error ? `History index failed: ${packet.error}` : "History index failed.");
	        return;
	      }
	      historyTurnIndexes[sessionKey] = Array.isArray(packet.turns) ? packet.turns : [];
	      if (sessionKey === selectedControlSessionKey) renderControlModal(true);
	    }

	    function handleResumeCandidatesPacket(packet) {
	      const sessionKey = String(packet.session_key || "");
	      delete resumeCandidateRequests[sessionKey];
	      if (!packet.ok) {
	        showUiMessage(packet.error ? `Resume lookup failed: ${packet.error}` : "Resume lookup failed.");
	        return;
	      }
	      resumeCandidateIndexes[sessionKey] = Array.isArray(packet.candidates) ? packet.candidates : [];
	      if (sessionKey === selectedControlSessionKey) renderControlModal(true);
	      if (sessionKey === selectedLauncherSessionKey) {
	        renderLauncherBar({ control_plane: latestControlPlane });
	      }
	    }

	    function clearPendingSessionLookups() {
	      for (const key of Object.keys(observedTurnRequests)) delete observedTurnRequests[key];
	      for (const key of Object.keys(historyTurnRequests)) delete historyTurnRequests[key];
	      for (const key of Object.keys(historyIndexRequests)) delete historyIndexRequests[key];
	      for (const key of Object.keys(resumeCandidateRequests)) delete resumeCandidateRequests[key];
	      for (const key of Object.keys(terminalSnapshotRequests)) delete terminalSnapshotRequests[key];
	      clearTerminalSnapshotRefresh();
	    }

    function connect() {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      const url = new URL("/api/ui-ws", window.location.href);
      url.protocol = location.protocol === "https:" ? "wss:" : "ws:";
      socket = new WebSocket(url.toString());
	      socket.addEventListener("open", () => {
	        setConnection("Live", "");
	        renderLauncherBar({ control_plane: latestControlPlane });
	        updateControlHeaderActions(selectedControlSession());
	        renderPermissionModal();
	        scheduleNextQuotaRefresh(250);
	      });
      socket.addEventListener("message", (event) => {
        try {
          const packet = JSON.parse(event.data);
          if (packet.type === "state") {
            scheduleRender(packet);
          } else if (packet.type === "state_delta") {
            scheduleRender(packet);
	        } else if (packet.type === "history_turn") {
	          handleHistoryTurnPacket(packet);
	        } else if (packet.type === "control_turn") {
	          handleObservedTurnPacket(packet);
	        } else if (packet.type === "history_index") {
	          handleHistoryIndexPacket(packet);
	        } else if (packet.type === "resume_candidates") {
	          handleResumeCandidatesPacket(packet);
	        } else if (packet.type === "terminal_snapshot") {
	          handleTerminalSnapshotPacket(packet);
	        } else if (packet.type === "heartbeat") {
            latestLiveBusy = Boolean(packet.live_busy);
            setConnection("Live", latestLiveBusy ? "busy" : "");
          }
        } catch {
          setConnection("Live", "");
        }
      });
	      socket.addEventListener("close", () => {
	        clearPendingSessionLookups();
	        quotaRefreshInFlight = "";
	        setConnection("Disconnected", "disconnected");
	        renderLauncherBar({ control_plane: latestControlPlane });
	        updateControlHeaderActions(selectedControlSession());
	        renderPermissionModal();
	        reconnectTimer = setTimeout(() => {
	          fetch("/api/ui-session", {
	            cache: "no-store",
	            credentials: "same-origin"
	          }).finally(connect);
	        }, 1500);
	      });
	      socket.addEventListener("error", () => {
	        clearPendingSessionLookups();
	        quotaRefreshInFlight = "";
	        setConnection("Disconnected", "disconnected");
	        renderLauncherBar({ control_plane: latestControlPlane });
	        updateControlHeaderActions(selectedControlSession());
	      });
    }

	    document.addEventListener("submit", async (event) => {
      const form = event.target.closest("form[data-action]");
      if (!form) return;
	      if (!socket || socket.readyState !== WebSocket.OPEN) return;
	      event.preventDefault();
	      const action = form.dataset.action;
	      const profile = form.dataset.profile || "";
	      const confirmMessage = form.dataset.confirm || "";
	      if (action === "consume_reset_credit") {
	        let credits = [];
	        try {
	          const parsed = JSON.parse(form.dataset.resetCredits || "[]");
	          credits = usableResetCredits(parsed);
	        } catch {
	          credits = [];
	        }
	        const choice = await chooseResetCredit(credits);
	        if (!choice) return;
	        const creditInput = form.querySelector('input[name="credit_id"]');
	        if (creditInput) creditInput.value = choice.creditId;
	      } else if (confirmMessage) {
	        const confirmed = await confirmAction({
	          title: action === "consume_reset_credit" ? "Use reset credit" : "Confirm action",
	          message: confirmMessage,
	          acceptLabel: action === "consume_reset_credit" ? "Use credit" : "Confirm",
	          danger: action === "consume_reset_credit"
	        });
	        if (!confirmed) return;
	      }
	      if ((action === "refresh_quota" || action === "consume_reset_credit") && profile) {
	        quotaRefreshAttempted.add(profile);
	        let queuedIndex = quotaRefreshQueue.indexOf(profile);
	        while (queuedIndex !== -1) {
	          quotaRefreshQueue.splice(queuedIndex, 1);
	          queuedIndex = quotaRefreshQueue.indexOf(profile);
	        }
	        quotaRefreshInFlight = profile;
	      }
      socket.send(JSON.stringify({
        ...Object.fromEntries(new FormData(form).entries()),
        action,
        profile,
	      }));
	    });

	    document.getElementById("profileHiddenToggle").addEventListener("click", () => {
	      showHiddenProfiles = !showHiddenProfiles;
	      renderProfileRows(
	        latestStatus && Array.isArray(latestStatus.profiles) ? latestStatus.profiles : [],
	        latestStatus && Array.isArray(latestStatus.provider_profiles) ? latestStatus.provider_profiles : [],
	        "",
	        ""
	      );
	    });

	    document.addEventListener("toggle", (event) => {
	      const menu = event.target;
	      if (!(menu instanceof HTMLDetailsElement)) return;
	      const type = menuType(menu);
	      if (!type) return;
	      const selector = menuSelector(type);
	      if (menu.open) {
	        setOpenMenuProfile(type, menu.dataset.profile || "");
	        document.querySelectorAll(`${selector}[open]`).forEach((other) => {
	          if (other !== menu) other.open = false;
	        });
	      } else if (getOpenMenuProfile(type) === (menu.dataset.profile || "")) {
	        setOpenMenuProfile(type, null);
	        if (type === "model") {
	          openReasoningProfile = null;
	          openReasoningModel = null;
	        }
	      }
	    }, true);

	    document.addEventListener("mouseover", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
	      const option = target.closest(".model-option");
	      if (!option) return;
	      const menu = option.closest("details.model-menu");
	      if (!menu || !menu.open) return;
	      openReasoningProfile = menu.dataset.profile || null;
	      openReasoningModel = option.dataset.model || null;
	      document.querySelectorAll(".model-option.reasoning-open").forEach((item) => {
	        if (item !== option) item.classList.remove("reasoning-open");
	      });
	      option.classList.add("reasoning-open");
	    });

	    document.addEventListener("focusin", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
	      const option = target.closest(".model-option");
	      if (!option) return;
	      const menu = option.closest("details.model-menu");
	      if (!menu || !menu.open) return;
	      openReasoningProfile = menu.dataset.profile || null;
	      openReasoningModel = option.dataset.model || null;
	      option.classList.add("reasoning-open");
	    });

	    document.addEventListener("click", (event) => {
	      const target = event.target;
	      if (
	        target instanceof Element
	        && target.closest("details.pin-menu, details.model-menu, details.login-menu")
	      ) return;
	      closeOpenMenus();
	    });

	    document.addEventListener("pointerover", showUiTooltip);
	    document.addEventListener("pointermove", (event) => {
	      const target = uiTooltipTarget(event.target);
	      if (target) positionUiTooltip(event, target);
	    });
	    document.addEventListener("pointerout", (event) => {
	      const next = event.relatedTarget;
	      if (next instanceof Element && uiTooltipTarget(next)) return;
	      hideUiTooltip();
	    });
	    document.addEventListener("focusin", showUiTooltip);
	    document.addEventListener("focusout", hideUiTooltip);

	    document.getElementById("launcherSession").addEventListener("change", (event) => {
	      selectedLauncherSessionKey = event.target.value || "";
	      launcherResumeSessionId = "";
	      renderLauncherBar({ control_plane: latestControlPlane });
	    });

	    document.getElementById("launcherMode").addEventListener("change", (event) => {
	      launcherMode = event.target.value || "new";
	      renderLauncherBar({ control_plane: latestControlPlane });
	    });

	    document.getElementById("launcherPermission").addEventListener("change", (event) => {
	      launcherPermission = event.target.value || "workspace-write";
	    });

		    document.getElementById("launcherResumeSession").addEventListener("change", (event) => {
		      launcherResumeSessionId = event.target.value || "";
		      renderLauncherBar({ control_plane: latestControlPlane });
		    });

	    document.getElementById("launcherStart").addEventListener("click", () => {
	      const sessionId = launcherMode === "resume-session" ? launcherResumeSessionId : "";
	      if (launcherMode === "resume-session" && !sessionId) return;
	      sendLaunchSession(
	        selectedLauncherSessionKey,
	        launcherMode,
	        sessionId
	      );
	      launcherPanelOpen = false;
	      renderSessionTabs({ control_plane: latestControlPlane });
	      renderLauncherBar({ control_plane: latestControlPlane });
	    });

	    document.getElementById("launcherClose").addEventListener("click", () => {
	      launcherPanelOpen = false;
	      renderSessionTabs({ control_plane: latestControlPlane });
	      renderLauncherBar({ control_plane: latestControlPlane });
	    });

	    document.getElementById("controlTurnSelect").addEventListener("change", (event) => {
	      if (!selectedControlSessionKey) return;
	      const selectedTurn = event.target.value || "";
	      selectedControlTurnKeys[selectedControlSessionKey] = selectedTurn;
	      if (selectedTurn) manuallySelectedControlTurnKeys[selectedControlSessionKey] = selectedTurn;
	      else delete manuallySelectedControlTurnKeys[selectedControlSessionKey];
	      delete controlTurnPresentations[controlTurnPresentationKey(selectedControlSession())];
	      saveControlScroll();
	      renderControlModal(true);
	    });

	    document.getElementById("controlTurnSelect").addEventListener("pointerenter", () => {
	      controlTurnSelectInteracting = true;
	    });

	    document.getElementById("controlTurnSelect").addEventListener("pointerleave", () => {
	      controlTurnSelectInteracting = false;
	      updateControlHeaderActions(selectedControlSession());
	    });

	    document.getElementById("controlTurnSelect").addEventListener("focus", () => {
	      controlTurnSelectInteracting = true;
	    });

	    document.getElementById("controlTurnSelect").addEventListener("blur", () => {
	      controlTurnSelectInteracting = false;
	      updateControlHeaderActions(selectedControlSession());
	    });

	    document.getElementById("sessionTabs").addEventListener("click", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
		      const close = target.closest("[data-session-close]");
		      if (close) {
		        event.preventDefault();
		        event.stopPropagation();
		        forgetControlSession(close.dataset.sessionClose || "");
		        return;
		      }
	      const launchTab = target.closest("[data-launch-tab]");
	      if (launchTab) {
	        saveControlScroll();
			        resetControlPromptHistory();
		        launcherPanelOpen = true;
	        selectedControlSessionKey = "";
	        pendingControlRender = false;
	        document.getElementById("controlModal").hidden = true;
	        renderSessionTabs({ control_plane: latestControlPlane });
	        renderLauncherBar({ control_plane: latestControlPlane });
	        return;
	      }
	      const tab = target.closest(".session-tab");
	      if (!tab) return;
		      saveControlScroll();
		      resetControlPromptHistory();
		      launcherPanelOpen = false;
	      selectedControlSessionKey = tab.dataset.sessionKey || "";
	      selectedLauncherSessionKey = selectedControlSessionKey;
	      document.getElementById("controlModal").hidden = false;
	      renderSessionTabs({ control_plane: latestControlPlane });
	      renderLauncherBar({ control_plane: latestControlPlane });
	      updateControlDockGeometry();
	      renderControlModal(true);
	    });

		    document.getElementById("sessionTabs").addEventListener("dragstart", (event) => {
		      const target = event.target;
		      if (!(target instanceof Element)) return;
		      const tab = target.closest(".session-tab[data-session-key]");
		      if (!tab) return;
		      draggedSessionTabKey = tab.dataset.sessionKey || "";
		      tab.classList.add("dragging");
		      if (event.dataTransfer) {
		        event.dataTransfer.effectAllowed = "move";
		        event.dataTransfer.setData("text/plain", draggedSessionTabKey);
		      }
		    });

		    document.getElementById("sessionTabs").addEventListener("dragover", (event) => {
		      if (!draggedSessionTabKey) return;
		      const target = event.target;
		      if (!(target instanceof Element)) return;
		      const tab = target.closest(".session-tab[data-session-key]");
		      if (!tab || tab.dataset.sessionKey === draggedSessionTabKey) return;
		      event.preventDefault();
		      clearSessionTabDropClasses();
		      tab.classList.add(sessionTabDropPosition(tab, event) === "after" ? "drop-after" : "drop-before");
		    });

		    document.getElementById("sessionTabs").addEventListener("dragleave", (event) => {
		      const target = event.target;
		      if (!(target instanceof Element)) return;
		      const tab = target.closest(".session-tab[data-session-key]");
		      if (tab) tab.classList.remove("drop-before", "drop-after");
		    });

		    document.getElementById("sessionTabs").addEventListener("drop", (event) => {
	      if (!draggedSessionTabKey) return;
	      event.preventDefault();
	      const container = document.getElementById("sessionTabs");
		      const dragged = Array.from(container.querySelectorAll(".session-tab[data-session-key]"))
		        .find((tab) => tab.dataset.sessionKey === draggedSessionTabKey);
		      const target = event.target instanceof Element ? event.target.closest(".session-tab[data-session-key]") : null;
		      if (dragged && target && target !== dragged) {
		        const position = sessionTabDropPosition(target, event);
		        container.insertBefore(dragged, position === "after" ? target.nextSibling : target);
		        sendSessionTabOrder();
		      }
		      draggedSessionTabKey = "";
		      clearSessionTabDropClasses();
		    });

		    document.getElementById("sessionTabs").addEventListener("dragend", () => {
		      draggedSessionTabKey = "";
		      clearSessionTabDropClasses();
		    });

	    document.getElementById("controlForget").addEventListener("click", async () => {
		      await forgetControlSession(selectedControlSessionKey);
	    });

	    document.getElementById("controlClose").addEventListener("click", () => {
	      document.getElementById("controlModal").hidden = true;
	      selectedControlSessionKey = "";
	      clearTerminalSnapshotRefresh();
	      pendingControlRender = false;
	      renderSessionTabs({ control_plane: latestControlPlane });
	      renderLauncherBar({ control_plane: latestControlPlane });
	    });

	    document.getElementById("controlModal").addEventListener("click", (event) => {
	      if (event.target === event.currentTarget) {
	        event.currentTarget.hidden = true;
	        selectedControlSessionKey = "";
	        clearTerminalSnapshotRefresh();
	        pendingControlRender = false;
	        renderSessionTabs({ control_plane: latestControlPlane });
	        renderLauncherBar({ control_plane: latestControlPlane });
	      }
	    });

	    document.querySelectorAll("[data-control-view]").forEach((button) => {
	      button.addEventListener("click", () => {
	        saveControlScroll();
	        controlView = button.dataset.controlView || "discussion";
	        if (controlView !== "terminal") clearTerminalSnapshotRefresh();
	        renderControlModal(true);
	      });
	    });

	    document.getElementById("controlSearch").addEventListener("input", (event) => {
	      controlSearchText = event.target.value || "";
	      renderControlModal(true);
	    });

	    document.getElementById("controlContent").addEventListener("click", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
	      const priorShow = target.closest("[data-control-prior-show]");
	      if (priorShow && selectedControlSessionKey) {
	        const session = selectedControlSession();
	        const prior = controlTurnByKey(
	          controlTurns(session, Array.isArray(session && session.transcript) ? session.transcript : []),
	          priorShow.dataset.controlPriorShow || ""
	        );
	        if (prior) requestObservedTurn(session, prior);
	        const presentation = controlTurnPresentations[controlTurnPresentationKey(selectedControlSession())];
	        if (presentation) presentation.revealedKey = priorShow.dataset.controlPriorShow || "";
	        renderControlModal(true);
	        return;
	      }
	      const priorOpen = target.closest("[data-control-prior-open]");
	      if (priorOpen && selectedControlSessionKey) {
	        const priorKey = priorOpen.dataset.controlPriorOpen || "";
	        if (!priorKey) return;
	        selectedControlTurnKeys[selectedControlSessionKey] = priorKey;
	        manuallySelectedControlTurnKeys[selectedControlSessionKey] = priorKey;
	        delete controlTurnPresentations[controlTurnPresentationKey(selectedControlSession())];
	        renderControlModal(true);
	        return;
	      }
	      const turnMore = target.closest("[data-control-turn-more]");
	      if (turnMore && selectedControlSessionKey) {
	        const session = selectedControlSession();
	        const turn = controlTurnByKey(
	          controlTurns(session, Array.isArray(session && session.transcript) ? session.transcript : []),
	          turnMore.dataset.controlTurnMore || ""
	        );
	        const before = Number(turnMore.dataset.controlTurnBefore);
	        if (turn && Number.isFinite(before)) requestObservedTurn(session, turn, before);
	        return;
	      }
	      const windowButton = target.closest("[data-control-window]");
	      if (windowButton) {
	        const direction = windowButton.dataset.controlWindow || "";
	        const content = document.getElementById("controlContent");
	        const previousHeight = content ? content.scrollHeight : 0;
	        if (expandControlTranscriptWindow(direction)) {
	          renderControlModal(true);
	          if (direction === "above") {
	            requestAnimationFrame(() => {
	              const refreshed = document.getElementById("controlContent");
	              if (refreshed) refreshed.scrollTop += Math.max(0, refreshed.scrollHeight - previousHeight);
	            });
	          }
	        }
	        return;
	      }
	      const candidate = target.closest("[data-resume-candidate]");
	      if (candidate && selectedControlSessionKey) {
	        selectedResumeCandidateIds[selectedControlSessionKey] = candidate.dataset.resumeCandidate || "";
	        renderControlModal(true);
	        return;
	      }
	      const resumeAction = target.closest("[data-resume-action]");
	      if (resumeAction && selectedControlSessionKey) {
	        const selectedId = selectedResumeCandidateIds[selectedControlSessionKey] || "";
	        if (!selectedId) return;
	        sendLaunchSession(selectedControlSessionKey, resumeAction.dataset.resumeAction || "resume-session", selectedId);
	        return;
	      }
	      const button = target.closest(".control-show-more");
	      if (!button) return;
	      const key = button.dataset.messageKey || "";
	      if (!key) return;
	      expandedControlMessages[key] = !expandedControlMessages[key];
	      renderControlModal(true);
	    });

	    document.getElementById("controlContent").addEventListener("scroll", () => {
	      saveControlScroll();
	      updateControlScrollBadges();
	      finalizeControlTurnBridgeIfScrolledAway();
	    }, { passive: true });

	    document.getElementById("mobileFocusToggle").addEventListener("click", () => {
	      setMobileDiscussionFocus(!mobileDiscussionFocused);
	    });

	    document.getElementById("mobileFocusRestore").addEventListener("click", () => {
	      setMobileDiscussionFocus(false);
	      mobileFocusScrollLockUntil = Date.now() + MOBILE_FOCUS_SCROLL_LOCK_MS;
	      requestAnimationFrame(() => window.scrollTo({ top: document.documentElement.scrollHeight, behavior: "auto" }));
	    });

	    window.addEventListener("wheel", (event) => {
	      handleMobileBoundaryGesture(event.deltaY, event);
	    }, { passive: false });

	    window.addEventListener("touchstart", (event) => {
	      if (!event.touches.length || mobileGestureTargetsDiscussion(event.target)) {
	        mobileTouchStartY = null;
	        return;
	      }
	      mobileTouchStartY = event.touches[0].clientY;
	    }, { passive: true });

	    window.addEventListener("touchmove", (event) => {
	      if (mobileTouchStartY == null || !event.touches.length) return;
	      handleMobileBoundaryGesture(mobileTouchStartY - event.touches[0].clientY, event);
	    }, { passive: false });

	    window.addEventListener("touchend", () => {
	      mobileTouchStartY = null;
	    }, { passive: true });

	    window.addEventListener("resize", () => {
	      mobileControlDockAnchorY = null;
	      document.body.classList.remove("mobile-control-stuck");
	      if (!mobileLayoutActive()) {
	        resetMobileDiscussionFocus();
	        resetMobileComposerFocus();
	      }
	      syncDiscussionPaneVisibility();
	      updateControlDockGeometry();
	      requestAnimationFrame(updateMobileControlStickiness);
	    }, { passive: true });

	    window.addEventListener("scroll", updateMobileControlStickiness, { passive: true });

	    if (window.visualViewport) {
	      window.visualViewport.addEventListener("resize", updateControlDockGeometry, { passive: true });
	      window.visualViewport.addEventListener("scroll", updateControlDockGeometry, { passive: true });
	    }

	    document.getElementById("controlPrompt").addEventListener("focus", () => {
	      setMobileComposerFocus(true);
	    });

	    document.getElementById("controlPrompt").addEventListener("blur", () => {
	      window.setTimeout(() => {
	        if (document.activeElement !== document.getElementById("controlPrompt")) resetMobileComposerFocus();
	      }, 0);
	    });

	    document.getElementById("controlPrompt").addEventListener("input", () => {
		      resetControlPromptHistory();
	      updateControlComposeState(selectedControlSession());
	    });

	    document.getElementById("controlPrompt").addEventListener("keydown", (event) => {
		      if (handleControlPromptHistory(event)) return;
	      if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
	      event.preventDefault();
	      document.getElementById("controlCompose").requestSubmit();
	    });

	    document.getElementById("controlCompose").addEventListener("submit", (event) => {
	      event.preventDefault();
	      const prompt = document.getElementById("controlPrompt");
	      const text = prompt.value.trim();
	      if (!text || !selectedControlSessionKey) return;
	      if (!socket || socket.readyState !== WebSocket.OPEN) {
	        showUiMessage("Dashboard websocket is not connected.");
	        return;
	      }
	      socket.send(JSON.stringify({
	        action: "session_prompt",
	        session_key: selectedControlSessionKey,
	        prompt: text,
	      }));
	      delete manuallySelectedControlTurnKeys[selectedControlSessionKey];
	      prompt.value = "";
		      resetControlPromptHistory();
	      updateControlComposeState(selectedControlSession());
	    });

	    document.getElementById("controlPermissionsToggle").addEventListener("click", () => {
	      const session = selectedControlSession();
	      if (!session || !session.permission_routing_supported) return;
	      if (!socket || socket.readyState !== WebSocket.OPEN) return;
	      socket.send(JSON.stringify({
	        action: "set_permission_routing",
	        session_key: String(session.key || ""),
	        enabled: !Boolean(session.permission_routing_enabled),
	      }));
	    });

	    document.getElementById("permissionTerminal").addEventListener("click", () => {
	      resolvePermission("terminal");
	    });

	    document.getElementById("permissionDeny").addEventListener("click", () => {
	      resolvePermission("deny");
	    });

	    document.getElementById("permissionAllow").addEventListener("click", () => {
	      resolvePermission("allow");
	    });

	    function sendSessionEscape() {
	      if (!selectedControlSessionKey) return false;
	      const session = selectedControlSession();
	      if (!controlInteractionAvailable(session)) return false;
	      if (!socket || socket.readyState !== WebSocket.OPEN) {
	        showUiMessage("Dashboard websocket is not connected.");
	        return true;
	      }
	      socket.send(JSON.stringify({
	        action: "session_escape",
	        session_key: selectedControlSessionKey,
	      }));
	      return true;
	    }

	    document.addEventListener("keydown", (event) => {
	      if (event.key !== "Escape" || event.defaultPrevented || pendingConfirmation) return;
	      const modal = document.getElementById("controlModal");
	      if (!modal || modal.hidden) return;
	      const active = document.activeElement;
	      if (active && active.id === "controlSearch") return;
	      if (sendSessionEscape()) event.preventDefault();
	    });

	    document.getElementById("statsToggle").addEventListener("click", () => {
	      const modal = document.getElementById("statsModal");
		      setStatsOpen(!modal || modal.hidden);
	    });

	    document.getElementById("statsClose").addEventListener("click", () => {
		      setStatsOpen(false);
	    });

	    document.getElementById("statsModal").addEventListener("click", (event) => {
	      if (event.target === event.currentTarget) {
		        setStatsOpen(false);
	      }
	    });

	    document.getElementById("statsContent").addEventListener("change", (event) => {
	      const target = event.target;
	      if (!(target instanceof HTMLInputElement) || !target.classList.contains("stats-profile-check")) return;
	      statsVisibleProfiles[target.value] = target.checked;
	      renderStats(latestStats);
	    });

	    document.getElementById("statsContent").addEventListener("pointermove", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
	      const graph = target.closest(".stats-graph");
	      if (!graph) return;
	      updateStatsGraphHover(graph, event);
	    });

	    document.getElementById("statsContent").addEventListener("pointerdown", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
	      const graph = target.closest(".stats-graph");
	      if (!graph) return;
	      updateStatsGraphHover(graph, event);
	    });

	    document.getElementById("statsContent").addEventListener("pointerleave", (event) => {
	      const target = event.target;
	      if (!(target instanceof Element)) return;
	      const graph = target.closest(".stats-graph");
	      if (graph) hideStatsGraphHover(graph);
	    }, true);

	    document.getElementById("confirmCancel").addEventListener("click", () => {
	      closeConfirmation(false);
	    });

	    document.getElementById("confirmAccept").addEventListener("click", () => {
	      closeConfirmation(true);
	    });

	    document.getElementById("confirmModal").addEventListener("click", (event) => {
	      if (event.target === event.currentTarget) closeConfirmation(false);
	    });

	    document.getElementById("themeToggle").addEventListener("click", () => {
	      setTheme(effectiveTheme() === "dark" ? "light" : "dark");
	    });

	    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
	      if (!savedTheme()) {
	        document.documentElement.removeAttribute("data-theme");
	        updateThemeToggle();
	      }
	    });

	    document.addEventListener("keydown", (event) => {
	      if (event.key === "Escape" && pendingConfirmation) {
	        event.preventDefault();
	        closeConfirmation(false);
	      }
	    });

	    window.addEventListener("resize", () => {
	      updateControlDockGeometry();
	      renderControlModal(true);
	    });

	    document.addEventListener("selectionchange", () => {
	      if (!controlSelectionActive()) setTimeout(flushPendingControlRender, 0);
	    });

	    document.getElementById("controlModal").addEventListener("focusout", () => {
	      setTimeout(flushPendingControlRender, 0);
	    });

	    document.getElementById("controlModal").addEventListener("mouseup", () => {
	      setTimeout(flushPendingControlRender, 0);
	    });

	    document.getElementById("statsToggle").innerHTML = CHART_ICON;
	    updateThemeToggle();
	    render(INITIAL);
	    normalizeNativeTooltips(document);
	    connect();
