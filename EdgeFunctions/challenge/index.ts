import { createClient } from "npm:@supabase/supabase-js@2";

const CHALLENGE_TTL_MINUTES = 5;

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

  // Generate a cryptographically random challenge
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  const challenge = Array.from(randomBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // Store with expiration
  const expiresAt = new Date(
    Date.now() + CHALLENGE_TTL_MINUTES * 60 * 1000
  ).toISOString();

  const { error: insertError } = await supabase
    .from("device_attestation_challenges")
    .insert({
      user_id: user.id,
      challenge,
      expires_at: expiresAt,
    });

  if (insertError) {
    console.error("Failed to store challenge:", insertError.message);
    return new Response(
      JSON.stringify({ error: "Failed to generate challenge" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }

  // Clean up expired challenges for this user (best-effort)
  await supabase
    .from("device_attestation_challenges")
    .delete()
    .eq("user_id", user.id)
    .lt("expires_at", new Date().toISOString());

  return new Response(JSON.stringify({ challenge, expiresAt }), {
    headers: { "Content-Type": "application/json" },
  });
});
