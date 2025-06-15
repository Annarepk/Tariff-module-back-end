package service

import (
	"math"
	"tariff-module-backend/internal/model"
)

// CalculateCommission рассчитывает комиссию с учетом порогов (если есть)
func CalculateCommission(tariff model.Tariff, req model.CalcRequest) float64 {
	//// Пробуем получить пороговые правила
	//thresholdRules, err := db.GetThresholdRulesByTariffID(tariff.ID)
	//
	//if err == nil && len(thresholdRules) > 0 {
	//	for _, rule := range thresholdRules {
	//		if req.OperationCount >= rule.FromCount && req.OperationCount < rule.ToCount {
	//			if matchesConditions(rule, req) {
	//				return applyCommissionRule(rule, req.Amount)
	//			}
	//		}
	//	}
	//}

	// Заглушка для проверки порогов (удалить при добавлении БД)
	thresholdRules := getMockThresholdRules(tariff.ID)

	if len(thresholdRules) > 0 {
		for _, rule := range thresholdRules {
			if req.OperationCount >= rule.FromCount && req.OperationCount < rule.ToCount {
				if matchesConditions(rule, req) {
					return applyCommissionRule(rule, req.Amount)
				}
			}
		}
	}

	// Если порогов нет или ни один не подошёл — стандартный расчёт
	return applyCommissionRule(model.ThresholdRule{
		FixedFee:   tariff.FixedFee,
		PercentFee: tariff.PercentFee,
		MinFee:     tariff.MinFee,
		MaxFee:     tariff.MaxFee,
	}, req.Amount)
}

// Заглушка для проверки порогов (удалить при добавлении БД)
func getMockThresholdRules(tariffID int) []model.ThresholdRule {
	return []model.ThresholdRule{
		{
			FromCount:   0,
			ToCount:     10,
			PercentFee:  0,
			FixedFee:    0,
			CalcMode:    "sum",
			MCC:         "", // любые MCC
			ClientType:  "", // любые клиенты
			AccountType: "", // любые счета
			OpType:      "", // любые операции
		},
		{
			FromCount:   10,
			ToCount:     50,
			PercentFee:  0.02,
			FixedFee:    10,
			CalcMode:    "sum",
			MCC:         "5411",
			ClientType:  "personal",
			AccountType: "debit",
			OpType:      "purchase",
		},
		{
			FromCount:   50,
			ToCount:     9999,
			PercentFee:  0.03,
			FixedFee:    15,
			CalcMode:    "max",
			MCC:         "", // любые MCC
			ClientType:  "", // любые клиенты
			AccountType: "", // любые счета
			OpType:      "", // любые операции
		},
	}
}

// applyCommissionRule — применение одной схемы комиссии
func applyCommissionRule(rule model.ThresholdRule, amount float64) float64 {
	var base float64

	percent := amount * rule.PercentFee
	fixed := rule.FixedFee

	switch rule.CalcMode {
	case "min":
		base = math.Min(fixed, percent)
	case "max":
		base = math.Max(fixed, percent)
	default: // "sum"
		base = fixed + percent
	}

	if base < rule.MinFee {
		return rule.MinFee
	}
	if rule.MaxFee > 0 && base > rule.MaxFee {
		return rule.MaxFee
	}

	return base
}

// matchesConditions проверяет соответствие доп. условий
func matchesConditions(rule model.ThresholdRule, req model.CalcRequest) bool {
	return (rule.MCC == "" || rule.MCC == req.MCC) &&
		(rule.ClientType == "" || rule.ClientType == req.ClientType) &&
		(rule.AccountType == "" || rule.AccountType == req.AccountType) &&
		(rule.OpType == "" || rule.OpType == req.OperationType)
}

// ProcessKafkaCalculationWithTariff — расчёт комиссии по переданному тарифу (Kafka)
func ProcessKafkaCalculationWithTariff(req model.CalcRequest, tariff model.Tariff) model.CalcResponse {
	commission := CalculateCommission(tariff, req)

	return model.CalcResponse{
		Product:        tariff.Name,
		Commission:     commission,
		OperationCount: req.OperationCount,
	}
}
