import { describe, expect, it } from "vitest";
import { parseLinkedInRawText } from "./linkedin.js";

describe("linkedin parser", () => {
  it("handles empty or blank text gracefully", () => {
    expect(parseLinkedInRawText("")).toEqual([]);
    expect(parseLinkedInRawText("   \n\n  ")).toEqual([]);
  });

  it("parses raw accessibility text into structured conversation threads", () => {
    const sampleDump = `
View Sladjana M.Rizvic’s profile
Sladjana M.Rizvic - Thunder
Talent Expert at Strike
Sladjana M.Rizvic - Thunder sent the following message at 6:50 AM
Hey Ron! So good to hear from you again! We aren't actively hiring SRE right now.
You: Well im here, at your service as always!
`;

    const threads = parseLinkedInRawText(sampleDump);
    expect(threads.length).toBe(1);
    expect(threads[0].participant).toBe("Sladjana M.Rizvic");
    expect(threads[0].messages.length).toBeGreaterThanOrEqual(1);
    expect(threads[0].messages.some((m) => m.text.includes("actively hiring"))).toBe(true);
  });
});
