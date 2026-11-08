import { authAdmin, dbAdmin, clientIp, ipHash, sendJson, requireModerator, FieldValue } from "./_admin.js";

export default async function handler(req,res) {
  try {
    const db=dbAdmin();
    if (req.method==="GET" && req.query?.action==="moderator-check") {
      const moderator=await requireModerator(req);
      return sendJson(res,200,{isModerator:true});
    }
    if (req.method==="GET") {
      if (req.query?.action==="moderators") {
        await requireModerator(req);
        const snapshot=await db.collection("moderators").where("active","==",true).get();
        const ids=new Set(snapshot.docs.map(d=>d.id));
        if (moderator.email?.toLowerCase()==="nico@accounts.mxprofiles.invalid") ids.add(moderator.uid);
        return sendJson(res,200,{moderators:[...ids]});
      }
      if (req.query?.action==="ip-bans") {
        const moderator=await requireModerator(req);
        const snapshot=await db.collection("ipBans").get();
        const bans=snapshot.docs.filter(d=>d.data().active!==false).map(d=>({id:d.id,reason:d.data().reason||"Blocked by moderator",updatedAt:d.data().updatedAt?.toDate?.()?.toISOString()||null}));
        return sendJson(res,200,{bans});
      }
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
    if (body.action==="moderator-grant" || body.action==="moderator-revoke") {
      const uid=String(body.uid||"").trim();
      if (!/^[A-Za-z0-9_-]{20,128}$/.test(uid)) return sendJson(res,400,{error:"Invalid member ID."});
      if (uid===moderator.uid) return sendJson(res,400,{error:"You cannot change your own moderator status."});
      const profileRef=db.doc("profiles/"+uid);
      const profile=await profileRef.get();
      if (!profile.exists) return sendJson(res,404,{error:"Member profile not found."});
      if (body.action==="moderator-grant") {
        await db.doc("moderators/"+uid).set({active:true,grantedAt:FieldValue.serverTimestamp(),grantedBy:moderator.uid},{merge:true});
        await profileRef.set({isModerator:true},{merge:true});
        return sendJson(res,200,{ok:true,isModerator:true});
      }
      await db.doc("moderators/"+uid).delete();
      await profileRef.set({isModerator:false},{merge:true});
      return sendJson(res,200,{ok:true,isModerator:false});
    }
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
    if (body.action==="ip-unban-hash") {
      const id=String(body.id||"");
      if (!/^[a-f0-9]{64}$/.test(id)) return sendJson(res,400,{error:"Invalid ban ID."});
      await db.doc("ipBans/"+id).delete();
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
