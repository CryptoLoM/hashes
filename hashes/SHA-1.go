package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"time"
)

// --- Конфігурація Практикуму ---

const (
	HASH_ALGORITHM  = "SHA1"
	PREIMAGE_BITS   = 16
	BIRTHDAY_BITS   = 32
	NUM_EXPERIMENTS = 100
)

// --- Допоміжні функції ---

func calculateHash(data []byte) string {
	h := sha1.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func truncateHash(fullHash string, bits int) string {
	if bits == 0 {
		return ""
	}
	nibbles := bits / 4
	if len(fullHash) < nibbles {
		return fullHash
	}
	return fullHash[len(fullHash)-nibbles:]
}

func generateRandomMessage(msg string) string {
	b := []byte(msg)
	idx := rand.Intn(len(b))
	b[idx] = byte((int(b[idx]) + rand.Intn(255) + 1) % 256)
	return string(b)
}

// --- Реалізація Атак ---

func PreimageAttack(initialMsg string, isSequential bool, bits int) int {
	fullTargetHash := calculateHash([]byte(initialMsg))
	targetHash := truncateHash(fullTargetHash, bits)

	count := 0
	currentMsg := initialMsg

	for {
		count++

		var candidateMsg string
		if isSequential {
			candidateMsg = initialMsg + strconv.Itoa(count)
		} else {
			candidateMsg = generateRandomMessage(currentMsg)
			currentMsg = candidateMsg
		}

		fullCandidateHash := calculateHash([]byte(candidateMsg))
		candidateHash := truncateHash(fullCandidateHash, bits)

		if candidateHash == targetHash {
			return count
		}

		if count > 5000000 {
			return -1
		}
	}
}

// ВИПРАВЛЕНА Birthday Attack
func BirthdayAttack(initialMsg string, isSequential bool, bits int) int {
	// Зберігаємо: truncated_hash -> (повідомлення, повний хеш)
	type HashEntry struct {
		message  string
		fullHash string
	}
	seenHashes := make(map[string]HashEntry)

	count := 0
	currentMsg := initialMsg

	for {
		count++

		var candidateMsg string
		if isSequential {
			// Послідовне додавання до початкового повідомлення
			candidateMsg = initialMsg + strconv.Itoa(count)
		} else {
			// Випадкові модифікації
			candidateMsg = generateRandomMessage(currentMsg)
			currentMsg = candidateMsg
		}

		// Обчислюємо геш
		fullHash := calculateHash([]byte(candidateMsg))
		truncHash := truncateHash(fullHash, bits)

		// Перевіряємо, чи бачили цей усічений геш раніше
		if entry, found := seenHashes[truncHash]; found {
			// ВАЖЛИВО: Перевіряємо, що це різні повідомлення
			// (інакше це не колізія, а дублікат)
			if entry.message != candidateMsg {
				// Колізія знайдена!
				// fmt.Printf("Колізія! Повідомлення 1: %s (хеш: %s)\n", entry.message, entry.fullHash)
				// fmt.Printf("Повідомлення 2: %s (хеш: %s)\n", candidateMsg, fullHash)
				return count
			}
		}

		// Зберігаємо новий геш
		seenHashes[truncHash] = HashEntry{
			message:  candidateMsg,
			fullHash: fullHash,
		}

		if count > 5000000 {
			return -1
		}
	}
}

// --- Статистика ---

func calculateStatistics(results []int) (float64, float64) {
	if len(results) == 0 {
		return 0, 0
	}

	sum := 0.0
	for _, r := range results {
		sum += float64(r)
	}
	mean := sum / float64(len(results))

	varianceSum := 0.0
	for _, r := range results {
		varianceSum += math.Pow(float64(r)-mean, 2)
	}
	variance := varianceSum / float64(len(results)-1)

	return mean, variance
}

func main() {
	rand.Seed(time.Now().UnixNano())

	fmt.Printf("--- Комп'ютерний практикум №1: %s (Ускладнена форма) ---\n", HASH_ALGORITHM)
	fmt.Printf("Кількість запусків: %d\n", NUM_EXPERIMENTS)
	fmt.Printf("Складність пошуку прообразу (теоретична): O(2^%d) = %d спроб\n",
		PREIMAGE_BITS, 1<<PREIMAGE_BITS)
	// Теоретичне математичне очікування для Birthday Attack
	// E[n] ≈ √(π/2 × m) ≈ 1.253 × √m, де m = 2^BIRTHDAY_BITS
	birthdayExpected := math.Sqrt(math.Pi/2.0) * math.Sqrt(float64(1<<BIRTHDAY_BITS))
	fmt.Printf("Складність атаки днів народження (теоретична): O(√2^%d) ≈ %.0f спроб\n",
		BIRTHDAY_BITS, birthdayExpected)
	fmt.Println("----------------------------------------------------------------")

	// -------------------------------------------------------------------
	// 1. Атака Пошуку Прообразу (Preimage Attack)
	// -------------------------------------------------------------------
	fmt.Printf("\n## Атака Пошуку Прообразу (Preimage) - Усічення до %d бітів\n", PREIMAGE_BITS)

	preimageSeqResults := make([]int, 0, NUM_EXPERIMENTS)
	preimageRandResults := make([]int, 0, NUM_EXPERIMENTS)

	for i := 1; i <= NUM_EXPERIMENTS; i++ {
		initialMsg := fmt.Sprintf("Ваше_ПІБ_експеримент_%d_%d", i, rand.Intn(10000))

		resultSeq := PreimageAttack(initialMsg, true, PREIMAGE_BITS)
		if resultSeq > 0 {
			preimageSeqResults = append(preimageSeqResults, resultSeq)
		}

		resultRand := PreimageAttack(initialMsg, false, PREIMAGE_BITS)
		if resultRand > 0 {
			preimageRandResults = append(preimageRandResults, resultRand)
		}
	}

	meanSeq, varianceSeq := calculateStatistics(preimageSeqResults)
	meanRand, varianceRand := calculateStatistics(preimageRandResults)

	fmt.Printf("### Результати (Варіант 1: Послідовне)\n")
	fmt.Printf("Середнє (M): %.2f\n", meanSeq)
	fmt.Printf("Дисперсія (D): %.2f\n", varianceSeq)
	fmt.Printf("СКО: ±%.2f\n", math.Sqrt(varianceSeq))
	fmt.Printf("Відхилення від теорії: %.2f%%\n",
		math.Abs(meanSeq-float64(1<<PREIMAGE_BITS))/float64(1<<PREIMAGE_BITS)*100)

	fmt.Printf("\n### Результати (Варіант 2: Випадкові модифікації)\n")
	fmt.Printf("Середнє (M): %.2f\n", meanRand)
	fmt.Printf("Дисперсія (D): %.2f\n", varianceRand)
	fmt.Printf("СКО: ±%.2f\n", math.Sqrt(varianceRand))
	fmt.Printf("Відхилення від теорії: %.2f%%\n",
		math.Abs(meanRand-float64(1<<PREIMAGE_BITS))/float64(1<<PREIMAGE_BITS)*100)

	// -------------------------------------------------------------------
	// 2. Атака Днів Народження (Birthday Attack)
	// -------------------------------------------------------------------
	fmt.Printf("\n## Атака Днів Народження (Birthday) - Усічення до %d бітів\n", BIRTHDAY_BITS)

	birthdaySeqResults := make([]int, 0, NUM_EXPERIMENTS)
	birthdayRandResults := make([]int, 0, NUM_EXPERIMENTS)

	for i := 1; i <= NUM_EXPERIMENTS; i++ {
		initialMsg := fmt.Sprintf("Інше_ПІБ_експеримент_%d_%d", i, rand.Intn(10000))

		resultSeq := BirthdayAttack(initialMsg, true, BIRTHDAY_BITS)
		if resultSeq > 0 {
			birthdaySeqResults = append(birthdaySeqResults, resultSeq)
		}

		resultRand := BirthdayAttack(initialMsg, false, BIRTHDAY_BITS)
		if resultRand > 0 {
			birthdayRandResults = append(birthdayRandResults, resultRand)
		}
	}

	meanSeq, varianceSeq = calculateStatistics(birthdaySeqResults)
	meanRand, varianceRand = calculateStatistics(birthdayRandResults)

	// Теоретичне математичне очікування: E[n] = √(π/2 × 2^BIRTHDAY_BITS)
	expectedBirthday := math.Sqrt(math.Pi/2.0) * math.Sqrt(float64(1<<BIRTHDAY_BITS))

	fmt.Printf("### Результати (Варіант 1: Послідовне)\n")
	fmt.Printf("Середнє (M): %.2f\n", meanSeq)
	fmt.Printf("Дисперсія (D): %.2f\n", varianceSeq)
	fmt.Printf("СКО: ±%.2f\n", math.Sqrt(varianceSeq))
	fmt.Printf("Теоретичне очікування: %.2f спроб\n", expectedBirthday)
	fmt.Printf("Відхилення від теорії: %.2f%%\n",
		math.Abs(meanSeq-expectedBirthday)/expectedBirthday*100)

	fmt.Printf("\n### Результати (Варіант 2: Випадкові модифікації)\n")
	fmt.Printf("Середнє (M): %.2f\n", meanRand)
	fmt.Printf("Дисперсія (D): %.2f\n", varianceRand)
	fmt.Printf("СКО: ±%.2f\n", math.Sqrt(varianceRand))
	fmt.Printf("Теоретичне очікування: %.2f спроб\n", expectedBirthday)
	fmt.Printf("Відхилення від теорії: %.2f%%\n",
		math.Abs(meanRand-expectedBirthday)/expectedBirthday*100)

	// Порівняння ефективності
	fmt.Println("\n----------------------------------------------------------------")
	fmt.Println("## Аналіз результатів:")
	fmt.Printf("\n### Preimage Attack (16 біт):\n")
	fmt.Printf("  Теоретично: 2^16 = 65,536 спроб\n")
	fmt.Printf("  Практично (послідовне): %.0f спроб (%.1f%% від теорії)\n",
		meanSeq, (meanSeq/float64(1<<PREIMAGE_BITS))*100)

	birthdayTheory := math.Sqrt(math.Pi/2.0) * math.Sqrt(float64(1<<BIRTHDAY_BITS))
	fmt.Printf("\n### Birthday Attack (32 біт):\n")
	fmt.Printf("  Теоретично: √(π/2 × 2^32) ≈ %.0f спроб\n", birthdayTheory)
	fmt.Printf("  Практично (послідовне): %.0f спроб (%.1f%% від теорії)\n",
		meanSeq, (meanSeq/birthdayTheory)*100)

	fmt.Printf("\n### Висновок:\n")
	fmt.Printf("  Birthday Attack з %d бітами еквівалентна Preimage Attack з %d бітами\n",
		BIRTHDAY_BITS, BIRTHDAY_BITS/2)
	fmt.Printf("  Обидві мають складність O(2^%d) ≈ 65,536-82,000 спроб\n", BIRTHDAY_BITS/2)
}
