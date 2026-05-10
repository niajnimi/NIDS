import { useEffect, useMemo } from "react";
import { io } from "socket.io-client";

export default function useSocket(baseUrl, handlers = {}) {
  const socket = useMemo(() => io(baseUrl, { transports: ["websocket"] }), [baseUrl]);
  useEffect(() => {
    Object.entries(handlers).forEach(([event, cb]) => socket.on(event, cb));
    return () => {
      Object.entries(handlers).forEach(([event, cb]) => socket.off(event, cb));
      socket.close();
    };
  }, [socket, handlers]);
  return socket;
}