import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evaluateRecruiterThreat, type ThreatEvaluation } from "./threat-intel.js";
import { log as rootLog } from "@job-scout/shared";

const execFileAsync = promisify(execFile);
const log = rootLog.child({ scope: "linkedin" });

export type LinkedInMessage = {
  sender: string;
  text: string;
  time?: string;
  isMe?: boolean;
};

export type LinkedInThread = {
  id: string;
  participant: string;
  headline?: string;
  lastMessage: string;
  lastMessageTime?: string;
  isUnread?: boolean;
  messages: LinkedInMessage[];
  threatScreen?: ThreatEvaluation;
};

export type LinkedInFeedResult = {
  source: "macos-accessibility" | "mock" | "empty";
  threads: LinkedInThread[];
  unreadCount: number;
  threatsDetected: number;
};

/**
 * Parses raw text extracted from LinkedIn Messaging UI into structured threads.
 */
export function parseLinkedInRawText(rawText: string): LinkedInThread[] {
  if (!rawText || rawText.trim().length === 0) return [];

  const threads: LinkedInThread[] = [];
  // Detect conversation blocks
  // Common markers: "View ...'s profile", "Active conversation", "sent the following message at"
  const lines = rawText.split("\n").map((l) => l.trim()).filter(Boolean);

  let currentParticipant = "Unknown";
  let currentMessages: LinkedInMessage[] = [];
  let headline = "";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Marker for participant name or profile
    if (line.startsWith("View ") && line.includes("’s profile")) {
      const match = line.match(/View (.*?)’s profile/);
      if (match && match[1]) {
        currentParticipant = match[1];
      }
    } else if (line.includes("sent the following message at") || line.includes("sent the following messages at")) {
      const senderMatch = line.match(/^(.*?)\s+sent the following message/);
      const sender = senderMatch ? senderMatch[1] : currentParticipant;
      const nextLine = lines[i + 1] || "";
      if (nextLine && !nextLine.startsWith("View ") && !nextLine.includes("sent the following")) {
        currentMessages.push({
          sender,
          text: nextLine,
          isMe: sender.toLowerCase().includes("you") || sender.toLowerCase().includes("ron"),
        });
      }
    } else if (line.startsWith("You: ") || line.startsWith("You sent ")) {
      currentMessages.push({
        sender: "You",
        text: line.replace(/^You:\s*/, ""),
        isMe: true,
      });
    } else if (line.includes("Just a ") || line.includes("Recruiter") || line.includes("Talent")) {
      if (!headline) headline = line;
    }
  }

  if (currentParticipant !== "Unknown" || currentMessages.length > 0) {
    const lastMsg = currentMessages[currentMessages.length - 1];
    threads.push({
      id: `thread-${currentParticipant.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
      participant: currentParticipant,
      headline: headline || undefined,
      lastMessage: lastMsg?.text || "",
      lastMessageTime: lastMsg?.time || "Recent",
      messages: currentMessages,
    });
  }

  return threads;
}

/**
 * AppleScript to query LinkedIn Messaging tab via macOS Accessibility framework.
 */
const SCRIPT_READ_LINKEDIN = `
tell application "System Events"
    set res to ""
    try
        tell process "Google Chrome"
            set value of attribute "AXEnhancedUserInterface" to true
            set wList to every window whose name contains "Messaging | LinkedIn"
            if (count of wList) is 0 then
                set wList to every window whose name contains "LinkedIn"
            end if
            if (count of wList) > 0 then
                set w to first item of wList
                set allElements to entire contents of w
                repeat with anItem in allElements
                    try
                        if role of anItem is "AXStaticText" then
                            set v to value of anItem
                            if v is not missing value and length of (v as text) > 1 then
                                set res to res & (v as text) & "\n"
                            end if
                        end if
                    end try
                end repeat
            end if
        end tell
    end try
    return res
end tell
`;

/**
 * Reads live LinkedIn messages from the local macOS Chrome session.
 */
export async function readLinkedInMessages(options?: {
  autoScreenThreats?: boolean;
}): Promise<LinkedInFeedResult> {
  const autoScreen = options?.autoScreenThreats ?? true;

  if (process.platform !== "darwin") {
    log.debug("linkedin.read: skipped non-darwin");
    return { source: "empty", threads: [], unreadCount: 0, threatsDetected: 0 };
  }

  try {
    const { stdout } = await execFileAsync("osascript", ["-e", SCRIPT_READ_LINKEDIN], {
      timeout: 10000,
      maxBuffer: 10 * 1024 * 1024,
    });

    const text = stdout.trim();
    if (!text) {
      return { source: "empty", threads: [], unreadCount: 0, threatsDetected: 0 };
    }

    const threads = parseLinkedInRawText(text);

    let threatsDetected = 0;
    if (autoScreen) {
      for (const t of threads) {
        // Evaluate threat for sender and last message
        const screen = await evaluateRecruiterThreat({
          domainOrEmail: t.participant,
          senderName: t.participant,
          messageText: t.lastMessage || t.messages.map((m) => m.text).join(" "),
        }, { skipRdap: true });

        t.threatScreen = screen;
        if (screen.isThreat) {
          threatsDetected++;
        }
      }
    }

    return {
      source: "macos-accessibility",
      threads,
      unreadCount: 0,
      threatsDetected,
    };
  } catch (err: unknown) {
    log.warn("linkedin.read_failed", { err: err instanceof Error ? err.message : String(err) });
    return { source: "empty", threads: [], unreadCount: 0, threatsDetected: 0 };
  }
}
