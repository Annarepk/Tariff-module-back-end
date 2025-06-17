package service

import (
	"math"
	"tariff-module-backend/internal/db"
	"tariff-module-backend/internal/model"
)

// CalculateCommission рассчитывает комиссию с учетом порогов (если есть)
func CalculateCommission(tariff model.Tariff, req model.CalcRequest) float64 {
	//// Пробуем получить пороговые правила
	thresholdRules, err := db.GetThresholdRulesByTariffID(tariff.ID)

	if err == nil && len(thresholdRules) > 0 {
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

// matchesConditions проверяет соответствие дополнительных условий
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
