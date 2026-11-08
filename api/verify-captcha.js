export default async function handler(req,res){
 if(req.method!=='POST'){res.setHeader('Allow','POST');return res.status(405).json({error:'Method not allowed.'})}
 try{
  const token=String(req.body?.turnstileToken||'');
  if(!token)return res.status(400).json({error:'Complete the CAPTCHA first.'});
  const secret=process.env.TURNSTILE_SECRET_KEY;
  if(!secret)return res.status(503).json({error:'CAPTCHA verification is not configured.'});
  const form=new URLSearchParams({secret,response:token});
  const ip=req.headers['x-real-ip']||req.headers['x-forwarded-for']?.split(',')[0]?.trim();
  if(ip)form.set('remoteip',ip);
  const check=await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:form});
  const result=await check.json();
  const allowed=['profiles.mxservers.online','localhost','127.0.0.1'];
  if(!result.success||!allowed.includes(result.hostname))return res.status(400).json({error:'CAPTCHA verification failed. Please try again.'});
  return res.status(200).json({success:true});
 }catch(error){console.error('MXProfile login CAPTCHA error:',error);return res.status(500).json({error:'Could not verify CAPTCHA. Please try again.'})}
}