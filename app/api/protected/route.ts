import { auth } from "auth"

const API_SERVER = 'http://localhost:9090'

export const GET = auth(async (req) => {
  if (req.auth) {
    try {
      const resp = await fetch(API_SERVER, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${req.auth.accessToken}`
        }
      })
      const json = await resp.text();
      return Response.json(json)
    } catch (e) {
      return Response.json({message: 'error!!'}, {status: 500})
    }
  }

  return Response.json({ message: "Not authenticated" }, { status: 401 })
}) as any
