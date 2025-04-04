
import { Loader2 } from "lucide-react";

interface TotalAmountProps {
  amount: number;
  originalAmount?: number;
  loading?: boolean;
  className?: string;
}

const TotalAmount = ({ 
  amount, 
  originalAmount, 
  loading = false,
  className = "" 
}: TotalAmountProps) => {
  const hasDiscount = originalAmount && originalAmount > amount;
  
  // Format amount with 2 decimal places, ensuring it's a valid number
  const formatAmount = (value: number | undefined): string => {
    if (value === undefined || value === null || isNaN(value)) {
      return '0.00';
    }
    return value.toFixed(2);
  };

  return (
    <div className={`col-span-2 mt-4 flex justify-end ${className}`}>
      <div className="bg-primary/5 p-3 rounded-md border border-primary/10">
        <p className="text-sm font-medium text-gray-500">Total Amount</p>
        {loading ? (
          <div className="flex items-center space-x-2">
            <Loader2 className="h-4 w-4 animate-spin text-primary" />
            <span className="text-sm">Calculating...</span>
          </div>
        ) : hasDiscount ? (
          <div className="flex flex-col">
            <p className="text-sm line-through text-gray-500">₹{formatAmount(originalAmount)}</p>
            <p className="text-xl font-bold text-primary">₹{formatAmount(amount)}</p>
          </div>
        ) : (
          <p className="text-xl font-bold">₹{formatAmount(amount)}</p>
        )}
      </div>
    </div>
  );
};

export default TotalAmount;
