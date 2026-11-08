import { authAdmin, dbAdmin, clientIp, ipHash, sendJson, FieldValue } from "./_admin.js";

export default async function handler(req, res) {
  if (req.method !== "POST") return sendJson(res,405,{error:"Method not allowed."});
  try {
    const ip = clientIp(req);
    if (!ip) return sendJson(res,403,{error:"Could not verify your network address."});
    const db = dbAdmin();
    const ipId = ipHash(ip);
    const ban = await db.doc("ipBans/"+ipId).get();
    if (ban.exists && ban.data().active !== false) return sendJson(res,403,{error:"Registration is unavailable from this network."});

    const settingsRef = db.doc("securitySettings/registration");
    const settingsSnap = await settingsRef.get();
    const settings = settingsSnap.exists ? settingsSnap.data() : { registrationsEnabled:true };
    if (settings.registrationsEnabled === false) return sendJson(res,403,{error:"Registrations are currently disabled."});

    const body = req.body || {};
    const username = String(body.username || "").trim().toLowerCase();
    const password = String(body.password || "");
    const token = String(body.turnstileToken || "");
    if (!/^[a-z0-9_]{1,64}$/.test(username)) return sendJson(res,400,{error:"Use 1–64 letters, numbers or underscores for your username."});
    if (password.length < 6 || password.length > 128) return sendJson(res,400,{error:"Password must be 6–128 characters."});
    if (!token) return sendJson(res,400,{error:"Complete the CAPTCHA first."});
    if (!process.env.TURNSTILE_SECRET_KEY) return sendJson(res,503,{error:"CAPTCHA verification is not configured yet."});

    const verifyBody = new URLSearchParams({secret:process.env.TURNSTILE_SECRET_KEY,response:token,remoteip:ip});
    const verifyResponse = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:verifyBody});
    const verification = await verifyResponse.json();
    if (!verification.success || verification.hostname !== "profiles.mxservers.online" && verification.hostname !== "localhost" && verification.hostname !== "127.0.0.1") {
      return sendJson(res,400,{error:"CAPTCHA verification failed. Please try again."});
    }

    const rateRef = db.doc("registrationRateLimits/"+ipId);
    const now = Date.now();
    const rateSnap = await rateRef.get();
    const rate = rateSnap.exists ? rateSnap.data() : {};
    if (rate.windowStart && now-rate.windowStart < 15*60*1000 && (rate.count||0)>=5) return sendJson(res,429,{error:"Too many registration attempts. Try again later."});
    await rateRef.set({windowStart:rate.windowStart && now-rate.windowStart<15*60*1000?rate.windowStart:now,count:rate.windowStart && now-rate.windowStart<15*60*1000?(rate.count||0)+1:1,updatedAt:FieldValue.serverTimestamp()});

    const usernameRef = db.doc("usernames/"+username);
    const existing = await usernameRef.get();
    if (existing.exists) return sendJson(res,409,{error:"That username is already taken."});
    const email = username+"@accounts.mxprofiles.invalid";
    const created = await authAdmin().createUser({email,password,displayName:username});
    try {
      await db.runTransaction(async tx => {
        const current = await tx.get(usernameRef);
        if (current.exists) throw new Error("That username is already taken.");
        const profileRef = db.doc("profiles/"+created.uid);
        tx.create(usernameRef,{uid:created.uid});
        tx.create(profileRef,{uid:created.uid,username,displayName:username,bio:"",accent:"#a78bfa",avatarUrl:"",socialUrl:"",createdAt:Date.now()});
      });
    } catch (error) {
      await authAdmin().deleteUser(created.uid).catch(()=>{});
      if (error.message==="That username is already taken.") return sendJson(res,409,{error:error.message});
      throw error;
    }
    const customToken = await authAdmin().createCustomToken(created.uid);
    return sendJson(res,201,{customToken});
  } catch (error) {
    console.error("MXProfile registration error:",error);
    return sendJson(res,error.status||500,{error:error.status?error.message:"Registration failed. Please try again later."});
  }
}
