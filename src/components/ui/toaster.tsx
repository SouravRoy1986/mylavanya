
import { useToast } from "@/hooks/use-toast"
import {
  Toast,
  ToastClose,
  ToastDescription,
  ToastProvider,
  ToastTitle,
  ToastViewport,
} from "@/components/ui/toast"

export function Toaster() {
  const { toasts } = useToast()

  return (
    <ToastProvider>
      {toasts.map(function ({ id, title, description, action, ...props }) {
        // Check if this is a booking success toast by looking for the booking reference
        const isBookingSuccess = typeof description === 'string' && 
          description.includes('booking reference number');

        let formattedDescription = description;
        
        // Format the booking reference if this is a booking success toast
        if (isBookingSuccess && typeof description === 'string') {
          // Split the description by newlines
          const lines = description.split('\n');
          
          // Process each line to enhance formatting
          formattedDescription = (
            <div className="space-y-2">
              {lines.map((line, index) => {
                // If this is the booking reference line
                if (line.includes('booking reference number')) {
                  const [before, after] = line.split(':');
                  return (
                    <div key={index} className="font-medium">
                      {before}:
                      <span className="text-2xl font-bold text-red-600 ml-2">
                        {after.trim()}
                      </span>
                    </div>
                  );
                }
                // Regular line
                else {
                  return <div key={index}>{line}</div>;
                }
              })}
            </div>
          );
        }

        return (
          <Toast 
            key={id} 
            {...props}
            style={{ pointerEvents: "auto" }}
          >
            <div className="grid gap-1">
              {title && <ToastTitle className="text-lg font-bold">{title}</ToastTitle>}
              {description && (
                <ToastDescription className="text-base">
                  {formattedDescription}
                </ToastDescription>
              )}
            </div>
            {action}
            <ToastClose />
          </Toast>
        )
      })}
      <ToastViewport />
    </ToastProvider>
  )
}
