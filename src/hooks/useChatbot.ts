import { useState, useCallback, useEffect } from "react";
import { ChatMessage, ChatbotState } from "@/types/chatbot";
import { useCustomToast } from "@/context/ToastContext";

// const API_ENDPOINT =
//   "https://n8n.srv896137.hstgr.cloud/webhook/621306e2-3aa9-4d20-97a2-22f85e25d694";

const API_ENDPOINT = "https://n8n.srv896137.hstgr.cloud/webhook/46ce558e-1b1c-4832-bf4f-ea96838d36dd";

export function useChatbot() {
  const [state, setState] = useState<ChatbotState>({
    messages: [],
    isLoading: false,
    isOpen: false,
    error: null,
    hasNewMessage: false,
  });
  const [hasShownWelcome, setHasShownWelcome] = useState(() => {
    return sessionStorage.getItem("chatbot_welcome_shown") === "true";
  });
  const { showToast } = useCustomToast();

  const generateId = () =>
    Date.now().toString() + Math.random().toString(36).substr(2, 9);

  // Generate or retrieve session ID that looks like a JWT token
  const getSessionId = useCallback(() => {
    let sessionId = sessionStorage.getItem("chatbot_session_id");
    if (!sessionId) {
      // Generate a JWT-like token (header.payload.signature format)
      const header = btoa(JSON.stringify({ typ: "JWT", alg: "HS256" }));
      const payload = btoa(
        JSON.stringify({
          sessionId: generateId(),
          timestamp: Date.now(),
          origin: window.location.origin,
        })
      );
      const signature = btoa(
        Math.random().toString(36).substr(2, 15) +
          Math.random().toString(36).substr(2, 15)
      );

      sessionId = `${header}.${payload}.${signature}`;
      sessionStorage.setItem("chatbot_session_id", sessionId);
    }
    return sessionId;
  }, []);

  // Play notification sound
  const playNotificationSound = useCallback(() => {
    try {
      // Create and resume audio context for better browser compatibility
      const audioContext = new (window.AudioContext ||
        (window as any).webkitAudioContext)();

      // Resume audio context if it's suspended (required for modern browsers)
      if (audioContext.state === "suspended") {
        audioContext.resume();
      }

      const oscillator = audioContext.createOscillator();
      const gainNode = audioContext.createGain();

      oscillator.connect(gainNode);
      gainNode.connect(audioContext.destination);

      oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
      oscillator.frequency.setValueAtTime(600, audioContext.currentTime + 0.1);

      gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(
        0.01,
        audioContext.currentTime + 0.3
      );

      oscillator.start(audioContext.currentTime);
      oscillator.stop(audioContext.currentTime + 0.3);
    } catch (error) {
      console.log("Audio not supported or failed:", error);
    }
  }, []);

  // Show welcome message after 5 seconds
  useEffect(() => {
    if (!hasShownWelcome) {
      const timer = setTimeout(() => {
        playNotificationSound();
        setHasShownWelcome(true);
        sessionStorage.setItem("chatbot_welcome_shown", "true");

        // Just set hasNewMessage to true to show tooltip-like behavior
        setState((prev) => ({
          ...prev,
          hasNewMessage: true,
        }));
      }, 5000);

      return () => clearTimeout(timer);
    }
  }, [hasShownWelcome, playNotificationSound]);

  const sendMessage = useCallback(
    async (content: string) => {
      if (!content.trim()) return;

      const userMessage: ChatMessage = {
        id: generateId(),
        content: content.trim(),
        sender: "user",
        timestamp: new Date(),
      };

      setState((prev) => ({
        ...prev,
        messages: [...prev.messages, userMessage],
        isLoading: true,
        error: null,
      }));

      try {
        const response = await fetch(API_ENDPOINT, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          mode: "cors",
          credentials: "omit", // Include cookies for session management
          body: JSON.stringify({
            chatInput: content.trim(),
            sessionId: getSessionId(),
          }),
        });
        console.log(response)
        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(
            `HTTP error! status: ${response.status}, message: ${errorText}`
          );
        }

        const responseText = await response.text();
        console.log("Raw API Response:", responseText);

        let data;
        try {
          data = JSON.parse(responseText);
        } catch (jsonError) {
          console.error("JSON Parse Error:", jsonError);
          console.error("Response that failed to parse:", responseText);
          throw new Error("Invalid JSON response from server");
        }

        // Check if response is empty, null, or contains no meaningful data
        const responseContent = data.response || "";
        const isEmptyResponse =
          !responseContent ||
          responseContent.trim() === "" ||
          responseContent.toLowerCase().includes("no data") ||
          responseContent.toLowerCase().includes("not found") ||
          responseContent.toLowerCase().includes("unable to find");

        let aiResponseContent;
        if (isEmptyResponse) {
          aiResponseContent =
            "I'm unable to process your request at the moment. For immediate assistance, please contact us at +91 9230967221. Our team will be happy to help you with your query.";
        } else {
          aiResponseContent = responseContent;
        }

        const aiMessage: ChatMessage = {
          id: generateId(),
          content: aiResponseContent,
          sender: "ai",
          timestamp: new Date(),
        };

        setState((prev) => ({
          ...prev,
          messages: [...prev.messages, aiMessage],
          isLoading: false,
        }));
      } catch (error) {
        console.error("Chatbot API error:", error);

        const fallbackMessage: ChatMessage = {
          id: generateId(),
          content:
            "I'm unable to process your request at the moment. For immediate assistance, please contact us at +91 9230967221. Our team will be happy to help you with your query.",
          sender: "ai",
          timestamp: new Date(),
        };

        setState((prev) => ({
          ...prev,
          messages: [...prev.messages, fallbackMessage],
          isLoading: false,
          error: null, // Clear error since we're showing a fallback message
        }));

        showToast(
          "❌ Connection issue. Please try again or contact support.",
          "error",
          4000
        );
      }
    },
    [showToast]
  );

  const toggleChat = useCallback(() => {
    setState((prev) => {
      const newState = {
        ...prev,
        isOpen: !prev.isOpen,
        hasNewMessage: false, // Clear notification when opening chat
      };

      // Add welcome message when opening chat for the first time
      if (!prev.isOpen && hasShownWelcome && prev.messages.length === 0) {
        const welcomeMessage: ChatMessage = {
          id: generateId(),
          content:
            "Hi! I'm Ananya, your assistant. What can I help you with today?",
          sender: "ai",
          timestamp: new Date(),
        };
        newState.messages = [welcomeMessage];
      }

      return newState;
    });
  }, [hasShownWelcome]);

  const clearError = useCallback(() => {
    setState((prev) => ({ ...prev, error: null }));
  }, []);

  const clearMessages = useCallback(() => {
    setState((prev) => ({ ...prev, messages: [] }));
  }, []);

  return {
    ...state,
    sendMessage,
    toggleChat,
    clearError,
    clearMessages,
  };
}
