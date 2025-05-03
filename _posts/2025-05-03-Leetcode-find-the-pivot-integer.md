## [Problem](https://leetcode.com/problems/find-the-pivot-integer/description/?envType=daily-question&envId=2024-03-13)
Given a positive integer n, find the pivot integer x such that:

The sum of all elements between 1 and x inclusively equals the sum of all elements between x and n inclusively.
Return the pivot integer x. If no such integer exists, return -1. It is guaranteed that there will be at most one pivot index for the given input.

## Solution

At first, I write the code that use prifix sum.
To avoid repeatedly caculating the sum within a range, I precomputed for each element. If a number is `x`, the sum from `1` to `x` is stored in `prefix_sum[x]`. I looped then form `n` down to `1`, checking if the number `n` is satisfies the condition:
- `(1, x)` equals `prefix_sum[x]`
- `(x, n)` equals `prefix_sum[n] - prefix_sum[x-1]`

If both sums are equal, `x` is the pivot, and I return it. If no such `x` is found after the loop, return `-1`.
```python
class Solution:
    def pivotInteger(self, n: int) -> int:
        prefix_sum = [0] * (n + 1)
        for i in range(1, n + 1):
            prefix_sum[i] = prefix_sum[i - 1] + i
        for pivot in range(n, 0, -1):
            if prefix_sum[n] - prefix_sum[pivot - 1] == prefix_sum[pivot]:
                return pivot
        return -1
```
However, this approach was slower than expected in terms of time complexity.
So, I referred to some discussion and rewrote the solution using a **mathematical approach**.

## Mathematical Insight
The sum of integers from `1` to `n` is `n(n+1)/2`.
Now let's define:
- `(1, x)` as `x(x + 1)/2`
- `(x, n)` as `n(n + 1)/2 - (x - 1)x/2`

Setting `(1, x) = (x, n)` leads to the equation:
```
x^2 = n(n + 1)/2
```

So, `x = sqrt(n(n + 1)/2)`.
If `x` is an integer, it is the pivot; otherwise, return `-1`.
```python
import math

class Solution:
    def pivotInteger(self, n: int) -> int:
        _sum = n * (n + 1) // 2
        x = math.sqrt(_sum)
        if x - math.ceil(x) == 0:
            return int(x)
        return -1
```
This method has **O(1)** time complexity, which is faster than the previous **O(n)** approach.
The discussion thread was titled "Math is everywhere" and I couldn't agree more. :)



