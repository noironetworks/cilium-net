package ecs

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Code generated by Alibaba Cloud SDK Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

// DepreciateInfo is a nested struct in ecs response
type DepreciateInfo struct {
	OriginalStandardPrice float64 `json:"OriginalStandardPrice" xml:"OriginalStandardPrice"`
	StartTime             string  `json:"StartTime" xml:"StartTime"`
	CheapRate             float64 `json:"CheapRate" xml:"CheapRate"`
	CheapStandardPrice    float64 `json:"CheapStandardPrice" xml:"CheapStandardPrice"`
	DifferentialName      string  `json:"DifferentialName" xml:"DifferentialName"`
	IsShow                bool    `json:"IsShow" xml:"IsShow"`
	MonthPrice            float64 `json:"MonthPrice" xml:"MonthPrice"`
	ListPrice             float64 `json:"ListPrice" xml:"ListPrice"`
	DifferentialPrice     float64 `json:"DifferentialPrice" xml:"DifferentialPrice"`
}