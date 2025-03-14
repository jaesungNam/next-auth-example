"use client"

import {useEffect} from "react";
import {signIn} from "next-auth/react";

const Page = () => {
  useEffect(() => {
    (async () => {
      const resp = await signIn('keycloak')
      if(resp?.ok) {
        console.log(resp)
      }
    })();
  }, [])
}

export default Page
