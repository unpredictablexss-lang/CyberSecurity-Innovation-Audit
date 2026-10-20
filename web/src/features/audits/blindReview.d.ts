export interface BlindReviewOperation {
  id: string;
  kind: string;
  status: string;
  result_sha256?: string | null;
  spec?: Record<string, any>;
}

export interface BlindReviewPair {
  key: string;
  operationIds: string[];
  label: string;
}

export function blindReviewPairs(operations: BlindReviewOperation[], experimentId?: string): {
  eligibleOperationCount: number;
  pairs: BlindReviewPair[];
  incompletePairCount: number;
  ambiguousPairCount: number;
};

export function blindReviewOperationIds(pairKeys: string[], pairs: BlindReviewPair[]): string[];
