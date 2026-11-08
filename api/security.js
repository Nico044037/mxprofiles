import { authAdmin, dbAdmin, clientIp, ipHash, sendJson, requireModerator, FieldValue } from "./_admin.js";

export default async function handler(req,res) {
  try {
    const db=dbAdmin();
    if (req.method==="GET") {
      const ip=clientIp(req);
      if (ip) {
        const ban=await db.doc("ipBans/"+ipHash(ip)).get();
        if (ban.exists && ban.data().active!==false) return sendJson(res,403,{error:"Access is unavailable from this network."});
      }
      const settings=await db.doc("securitySettings/registration").get();
      return sendJson(res,200,{siteKey:process.env.TURNSTILE_SITE_KEY||"",registrationsEnabled:settings.exists?settings.data().registrationsEnabled!==false:true});
    }
    if (req.method!=="POST") return sendJson(res,405,{error:"Method not allowed."});
    const moderator=await requireModerator(req);
    const body=req.body||{};
    if (body.action==="registrations") {
      if (typeof body.enabled!=="boolean") return sendJson(res,400,{error:"enabled must be boolean."});
      await db.doc("securitySettings/registration").set({registrationsEnabled:body.enabled,updatedAt:FieldValue.serverTimestamp(),updatedBy:moderator.uid},{merge:true});
      return sendJson(res,200,{ok:true,registrationsEnabled:body.enabled});
    }
    if (body.action==="ip-ban") {
      const ip=String(body.ip||"").trim();
      if (!ip || ip.length>64 || !/^[0-9a-fA-F:.]+$/.test(ip)) return sendJson(res,400,{error:"Enter a valid IPv4 or IPv6 address."});
      const id=ipHash(ip);
      await db.doc("ipBans/"+id).set({active:true,reason:String(body.reason||"Blocked by moderator").slice(0,300),updatedAt:FieldValue.serverTimestamp(),updatedBy:moderator.uid},{merge:true});
      return sendJson(res,200,{ok:true});
    }
    if (body.action==="ip-unban") {
      const ip=String(body.ip||"").trim();
      if (!ip || ip.length>64 || !/^[0-9a-fA-F:.]+$/.test(ip)) return sendJson(res,400,{error:"Enter a valid IPv4 or IPv6 address."});
      await db.doc("ipBans/"+ipHash(ip)).delete();
      return sendJson(res,200,{ok:true});
    }
    return sendJson(res,400,{error:"Unknown action."});
  } catch(error) {
    console.error("MXProfile security API error:",error);
    return sendJson(res,error.status||500,{error:error.status?error.message:"Security settings request failed."});
  }
}
