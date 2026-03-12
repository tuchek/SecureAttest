/**
 * Shared assertion verification utility.
 *
 * Import this in any Edge Function that needs to verify App Attest assertions.
 *
 * Usage in your Edge Function:
 * ```typescript
 * import { verifyRequestAssertion } from "../_shared/assert.ts";
 *
 * const attestationStatus = await verifyRequestAssertion(supabase, userId, {
 *   assertion: body.assertion,
 *   challenge: body.challenge,
 *   payload: body.payload,
 * });
 *
 * if (!attestationStatus.verified && attestationStatus.required) {
 *   return new Response("Assertion verification failed", { status: 403 });
 * }
 * ```
 */
import { SupabaseClient } from "npm:@supabase/supabase-js@2";
import { verifyAssertion } from "npm:node-app-attest";
import { Buffer } from "node:buffer";

export interface AssertionInput {
  assertion: string; // base64-encoded assertion data
  challenge: string; // the challenge used
  payload: string; // base64-encoded request payload
}

export interface AssertionStatus {
  /** Whether the assertion was successfully verified. */
  verified: boolean;
  /** Whether attestation exists for this user (determines if assertion is required). */
  required: boolean;
  /** Error message if verification failed. */
  error?: string;
}

/**
 * Verify an App Attest assertion for a user's request.
 *
 * - If the user has no attestation on file, returns `{ verified: false, required: false }`.
 *   This allows graceful degradation for devices that don't support App Attest.
 * - If the user has an attestation but the assertion is missing/invalid,
 *   returns `{ verified: false, required: true, error: "..." }`.
 * - If everything checks out, returns `{ verified: true, required: true }`.
 */
export async function verifyRequestAssertion(
  supabase: SupabaseClient,
  userId: string,
  input: AssertionInput | null
): Promise<AssertionStatus> {
  // Look up the user's attestation
  const { data: attestation, error: lookupError } = await supabase
    .from("device_attestations")
    .select()
    .eq("user_id", userId)
    .order("attested_at", { ascending: false })
    .limit(1)
    .single();

  if (lookupError || !attestation) {
    // No attestation on file — device doesn't support App Attest
    return { verified: false, required: false };
  }

  // Attestation exists — assertion is required
  if (!input || !input.assertion || !input.challenge) {
    return {
      verified: false,
      required: true,
      error: "Assertion required but not provided",
    };
  }

  // Verify the challenge
  const { data: challengeRecord, error: challengeError } = await supabase
    .from("device_attestation_challenges")
    .select()
    .eq("user_id", userId)
    .eq("challenge", input.challenge)
    .eq("consumed", false)
    .gt("expires_at", new Date().toISOString())
    .single();

  if (challengeError || !challengeRecord) {
    return {
      verified: false,
      required: true,
      error: "Invalid or expired challenge",
    };
  }

  // Consume the challenge
  await supabase
    .from("device_attestation_challenges")
    .update({ consumed: true })
    .eq("id", challengeRecord.id);

  // Build client data hash (must match what the client computed)
  const bundleIdentifier = Deno.env.get("APPLE_BUNDLE_ID")!;
  const teamIdentifier = Deno.env.get("APPLE_TEAM_ID")!;

  try {
    const result = await verifyAssertion({
      assertion: Buffer.from(input.assertion, "base64"),
      payload: Buffer.from(input.payload, "base64"),
      publicKey: attestation.public_key,
      bundleIdentifier,
      teamIdentifier,
      signCount: attestation.counter,
    });

    // Update the counter
    await supabase
      .from("device_attestations")
      .update({ counter: result.signCount })
      .eq("id", attestation.id);

    return { verified: true, required: true };
  } catch (err) {
    console.error("Assertion verification failed:", err);
    return {
      verified: false,
      required: true,
      error: "Assertion signature verification failed",
    };
  }
}
