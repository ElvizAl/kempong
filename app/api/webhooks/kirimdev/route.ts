import {
  InvalidSignatureError,
  MalformedPayloadError,
  SignatureExpiredError,
  verifyWebhookSignature,
} from "@kirimdev/sdk/webhooks";

export const runtime = "nodejs";

type WebhookBody = {
  entry?: Array<{
    changes?: Array<{
      value?: {
        metadata?: {
          phone_number_id?: string;
        };
        messages?: Array<{
          id?: string;
          from?: string;
          type?: string;
          text?: {
            body?: string;
          };
        }>;
      };
    }>;
  }>;
};

export async function POST(request: Request) {
  const rawBody = await request.text();

  const signature = request.headers.get("x-kirim-signature");
  const eventName = request.headers.get("x-kirim-event");

  try {
    const body = (await verifyWebhookSignature({
      rawBody,
      signatureHeader: signature,
      secrets: [process.env.KIRIM_WEBHOOK_SECRET!],
      toleranceSeconds: 300,
    })) as WebhookBody;

    // Abaikan event selain pesan masuk
    if (eventName !== "message.received") {
      return Response.json({
        ok: true,
        ignored: true,
      });
    }

    const value = body.entry?.[0]?.changes?.[0]?.value;
    const message = value?.messages?.[0];

    if (!message) {
      return Response.json({
        ok: true,
        ignored: true,
      });
    }

    const result = {
      messageId: message.id,
      phoneNumberId: value?.metadata?.phone_number_id,
      customerNumber: message.from,
      type: message.type,
      text: message.text?.body ?? null,
    };

    console.log("Pesan WhatsApp masuk:", result);

    return Response.json({
      ok: true,
      message: result,
    });
  } catch (error) {
    if (error instanceof SignatureExpiredError) {
      return new Response("Signature kedaluwarsa", {
        status: 400,
      });
    }

    if (error instanceof InvalidSignatureError) {
      return new Response("Signature tidak valid", {
        status: 401,
      });
    }

    if (error instanceof MalformedPayloadError) {
      return new Response("Payload tidak valid", {
        status: 400,
      });
    }

    console.error("Webhook error:", error);

    return new Response("Internal server error", {
      status: 500,
    });
  }
}