import { createClient } from "npm:@supabase/supabase-js@2";
import { verifyAttestation } from "npm:node-app-attest";
import { Buffer } from "node:buffer";

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const authHeader = req.headers.get("Authorization");
  if (!authHeader) {
    return new Response("Unauthorized", { status: 401 });
  }

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
  );

  // Verify the user's JWT
  const {
    data: { user },
    error: authError,
  } = await supabase.auth.getUser(authHeader.replace("Bearer ", ""));

  if (authError || !user) {
    return new Response("Unauthorized", { status: 401 });
  }

  // Parse request body
  const { keyId, attestation, challenge } = await req.json();

  if (!keyId || !attestation || !challenge) {
    return new Response(
      JSON.stringify({ error: "Missing required fields: keyId, attestation, challenge" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  // Verify challenge exists, belongs to this user, and hasn't expired
  const { data: challengeRecord, error: challengeError } = await supabase
    .from("device_attestation_challenges")
    .select()
    .eq("user_id", user.id)
    .eq("challenge", challenge)
    .eq("consumed", false)
    .gt("expires_at", new Date().toISOString())
    .single();

  if (challengeError || !challengeRecord) {
    return new Response(
      JSON.stringify({ error: "Invalid or expired challenge" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  // Consume the challenge (single-use)
  await supabase
    .from("device_attestation_challenges")
    .update({ consumed: true })
    .eq("id", challengeRecord.id);

  // Verify attestation using node-app-attest
  const teamIdentifier = Deno.env.get("APPLE_TEAM_ID");
  const bundleIdentifier = Deno.env.get("APPLE_BUNDLE_ID");
  const isDevelopment = Deno.env.get("ENVIRONMENT") !== "production";

  if (!teamIdentifier || !bundleIdentifier) {
    console.error("Missing APPLE_TEAM_ID or APPLE_BUNDLE_ID env vars");
    return new Response(
      JSON.stringify({ error: "Server configuration error" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }

  try {
    const result = await verifyAttestation({
      attestation: Buffer.from(attestation, "base64"),
      challenge: Buffer.from(challenge),
      keyId,
      bundleIdentifier,
      teamIdentifier,
      allowDevelopmentEnvironment: isDevelopment,
    });

    // Store the attested device (upsert — handles re-attestation)
    const { error: upsertError } = await supabase
      .from("device_attestations")
      .upsert(
        {
          user_id: user.id,
          key_id: keyId,
          public_key: result.publicKey,
          counter: 0,
          attested_at: new Date().toISOString(),
        },
        { onConflict: "user_id,key_id" }
      );

    if (upsertError) {
      console.error("Failed to store attestation:", upsertError.message);
      return new Response(
        JSON.stringify({ error: "Failed to store attestation" }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }

    return new Response(JSON.stringify({ success: true }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("Attestation verification failed:", err);
    return new Response(
      JSON.stringify({ error: "Attestation verification failed" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }
});
