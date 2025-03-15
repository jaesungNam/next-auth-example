"use client"

import {useEffect} from "react";
import {signIn} from "next-auth/react";
import {useSearchParams} from "next/navigation";

const Page = () => {
  const searchParams = useSearchParams();
  useEffect(() => {
    (async () => {
      const callbackUrl = searchParams.get('callback-url')
      if(callbackUrl) {
        window.location.href = callbackUrl;
        return;
      }
      const resp = await signIn('keycloak')
      if(resp?.ok) {
        console.log(resp)
      }
    })();
  }, [])

  return <div>
    <button onClick={() => {

    }}>로그인</button>

  </div>
}

export default Page
