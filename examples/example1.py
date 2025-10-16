def calculate_sum(n):
    total = 0
    for i in range(n):
        for j in range(n):
            total += i + j
    return total

for x in range(5):
    print(calculate_sum(x))
