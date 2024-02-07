import { SignatureV4 } from "@smithy/signature-v4";
import { HttpRequest }  from '@smithy/protocol-http';
import type {
  QueryParameterBag,
} from "@aws-sdk/types";
import {
  createHash,
  createHmac,
  type BinaryLike,
  type Hmac,
  type KeyObject,
} from "node:crypto";
import { CloudFrontRequestHandler } from 'aws-lambda';
import { parse } from 'node:querystring';

class Sha256 {
  private readonly hash: Hmac;

  public constructor(secret?: unknown) {
    this.hash = secret
      ? createHmac("sha256", secret as BinaryLike | KeyObject)
      : createHash("sha256");
  }

  public digest(): Promise<Uint8Array> {
    const buffer = this.hash.digest();

    return Promise.resolve(new Uint8Array(buffer.buffer));
  }

  public update(array: Uint8Array): void {
    this.hash.update(array);
  }
}

const signer = new SignatureV4({
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || "",
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || "",
    sessionToken: process.env.AWS_SESSION_TOKEN || "",
  },
  region: process.env.AWS_REGION || "us-east-1",
  service: "lambda",
  sha256: Sha256,
});

export const handler: CloudFrontRequestHandler = async (event) => {
  // Extract original request
  const request = event.Records[0].cf.request;
  const { headers, uri, body, method, querystring } = request;
  const host = headers.host[0].value;
  const url = new URL(
    `https://${host}${uri}${querystring ? `?${querystring}` : ""}`
  );
  const region = headers.host[0].value.split(".")[2];

  // Construct new request object for signing
  const requestToSign = new HttpRequest({
    hostname: url.hostname,
    path: url.pathname,
    method,
    headers: {},
    query: querystring ? (parse(querystring) as QueryParameterBag) : undefined,
    body: body?.data
      ? Buffer.from(body.data, body.encoding as BufferEncoding)
      : undefined,
  });
  // Add headers to request except for x-forwarded-for
  for (const [key, value] of Object.entries(headers)) {
    if (key === "x-forwarded-for") continue;
    requestToSign.headers[key] = value[0].value;
  }

  // Sign request
  const signedRequest = await signer.sign(requestToSign, {
    signingRegion: region,
  });


  // Add signed headers to original request
  for (const header in signedRequest.headers) {
    request.headers[header.toLowerCase()] = [
      {
        key: header,
        value: signedRequest.headers[header],
      },
    ];
  }

  // Return signed request
  return request;
};