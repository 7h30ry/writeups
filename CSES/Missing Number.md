# CSES Problem set

## Missing Number

## Question

You are given all numbers between 1,2,…,n except one. Your task is to find the missing number.

## Input

The first input line contains an integer n.

The second line contains n−1 numbers. Each number is distinct and between 1 and n (inclusive).

## Output

Print the missing number.

## Constraints

    2≤n≤2⋅105


## Example

Input:
5
2 3 1 5

Output:
4

## Solve script
```python
def missing_number(n, num):
    # Calculate the sum of integers from 1 to n
    total_sum = (n * ( n + 1 )) // 2
    # calculate the sum of the given numbers
    given_sum = sum(num)
    # The missing number is the difference between the total sum and the given sum
    return total_sum - given_sum

if __name__ == "__main__":
    n = int(input())
    num = list(map(int, input().split()))

    missingnumber =  missing_number(n, num)
    print(missingnumber)

```
