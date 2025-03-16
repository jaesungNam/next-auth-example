"use client"

import {useEffect} from "react";
import {signIn} from "next-auth/react";
import {useSearchParams} from "next/navigation";

const Page = () => {
  useEffect(() => {
    (async () => {
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
