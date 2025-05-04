import re
from nltk import word_tokenize


def task1_hit(sys,gold):
    """
    Distinguishing the prediction outcomes for individual samples in the task of identifying the existence of vulnerabilities: 
    True Positive, False Positive, True Negative, False Negative. 
    
    Args:
        sys(str):model output of task1:vulnerability existence detection.
        gold(str):expected label of the task1 sample:YES or NO.
        
    Returns:
        tuple of integers:indicating the model prediction is a 
        - tp: True Positive
        - fp: False Positive
        - tn: True Negative
        - fn: False Negative
    """
    sys_code=''
    if 'yes' in sys.lower() or 'is vulnerable' in sys.lower():
        sys_token=1
        sys_code='YES'
    else:
        sys_token=0
        sys_code='NO'

    if 'yes' in gold.lower() or 'is vulnerable' in gold.lower():
        gold_token=1
    else:
        gold_token=0
    
    tp=fp=tn=fn=0
    if sys_token==1 and gold_token==1:
        tp=1
    elif sys_token==1 and gold_token==0:
        fp=1
    elif sys_token==0 and gold_token==1:
        fn=1
    else:
        tn=1
    return (tp,fp,tn,fn),sys_code
    
def task1_acc(scores):
    """
    Calculating the overall accuracy in task1:vulnerability existence detection.
    
    Args:
        scores(list of integer lists):containing model prediction situation in each sample,in the form of [[tps],[fps],[tns],[fns]]
        
    Returns:
        float:overall accuracy on task1.
    """
    tps=[item[0] for item in scores]
    fps=[item[1] for item in scores]
    tns=[item[2] for item in scores]
    fns=[item[3] for item in scores]
    #[[tps],[fps],[tns],[fns]]
    TP=sum(tps)
    FP=sum(fps)
    TN=sum(tns)
    FN=sum(fns)
    acc=(TP+TN)/(TP+FP+TN+FN)
    return acc

def task1_f1(scores):
    """
    Calculating the overall f1-score in task1:vulnerability existence detection.
    
    Args:
        scores(list of integer lists):containing model prediction situation in each sample,in the form of [[tps],[fps],[tns],[fns]]
        
    Returns:
        float:overall f1-score on task1.
    """
    
    tps=[item[0] for item in scores]
    fps=[item[1] for item in scores]
    tns=[item[2] for item in scores]
    fns=[item[3] for item in scores]
    #[[tps],[fps],[tns],[fns]]
    TP=sum(tps)
    FP=sum(fps)
    TN=sum(tns)
    FN=sum(fns)
    
    try:
        p=TP/(TP+FN)
        r=TP/(TP+FP)
        f1=2*(p*r)/(p+r)
    except ZeroDivisionError:
        f1=0

    return f1

def task2_hit(sys : str, gold : str):
    """
    Check whether the model output contains the desired keywords(specific CWE type and discriptions)
    
    Args:
        sys(str):Model output of task2:CWE type inference.
        gold(str):desired CWE type and discriptions.
        
    Returns
        integer:if above 0,the model output contains keywords.Otherwise no.
    """
    
    pattern = re.compile(r"CWE[-|:| ]?\s?(\d{1,3})")
    
    sys = pattern.findall(sys)
    gold = pattern.findall(gold)

    # print("preds: ", preds)
    # print("gold: ", gold)

    intersection = len(set(sys).intersection(set(gold)))
    return intersection

def task2_se(sys : str, gold : str):
    """
    Calculating Strict Evaluation(SE) in task2:CWE type inference.
    SE: If the options include the optimal choice, score 1 point; if the options only include the suboptimal choice, score 0.5 points.
    
    Args:
        sys(str):model output of task2.
        gold(str):expected answer of task2:optimal choice+suboptimal choice.
        
    Returns:
        float:strict score model gets on this sample.
    """
    sys_code=''
    gold = gold.split('|')
    if len(gold) == 1:
        gold = [gold[0], gold[0]]
    
    answers = [gold[0][0], gold[1][0]]
    score_a = 0
    if (answers[1] + '.') in sys:
        score_a += 0.5
        sys_code=answers[1]

    if (answers[0] + '.') in sys:
        score_a += 1
        sys_code=answers[0]
    
    if score_a==1.5:
        score_a=0
        sys_code=''
    
    score_b = 0
    if task2_hit(sys, gold[0]) > 0:
        score_b += 1
        sys_code=answers[0]
    
    if task2_hit(sys, gold[1]) > 0:
        score_b += 0.5
        sys_code=answers[1]
    
    if score_b==1.5:
        score_b=0
        sys_code=''
    
    return max(score_a, score_b), sys_code

def task2_me(sys, gold):
    """
    Calculating Moderate Evaluation(SE) in task2:CWE type inference.
    ME: If the options include the optimal choice or suboptimal choice, score 1 point.
    
    Args:
        sys(str):model output of task2.
        gold(str):expected answer of task2:optimal choice+suboptimal choice.
        
    Returns:
        float:moderate score model gets on this sample.
    """
    gold = gold.split('|')
    if len(gold) == 1:
        gold = [gold[0], gold[0]]
        
    answers = [gold[0][0], gold[1][0]]
    
    score_a = 0
    sys_code=''
    if (answers[0] + '.') in sys :
        score_a = 1
        sys_code=answers[0]
    elif (answers[1] + '.') in sys:
        score_a=1
        sys_code=answers[1]

    score_b = 0
    if task2_hit(sys, gold[0]) > 0:
        score_b = 1
        sys_code = answers[0]
    elif task2_hit(sys, gold[1]) > 0:
        score_b = 1
        sys_code = answers[1]
            
    return max(score_a, score_b), sys_code

def task2_avg_se(scores):
    """
    Calculating average ME or SE on the entire task2 benchmark.
        
    Args:
        scores(list of floats):A list of scores model gets on each sample of task2.
        
    Returns:
        float:the average score on task2.
    """
    return sum(scores)/len(scores)

def task2_avg_me(scores):
    """
    Calculating average ME or SE on the entire task2 benchmark.
        
    Args:
        scores(list of floats):A list of scores model gets on each sample of task2.
        
    Returns:
        float:the average score on task2.
    """
    return sum(scores)/len(scores)


# define the mappings from eval string to eval function
MetricsMapping = {
    'hit': task1_hit,
    'Accuracy': task1_acc,
    'F1-Score': task1_f1,
    'Moderate Evaluation Score': task2_me,
    'Strict Evaluation Score': task2_se,
    'Avg Moderate Evaluation Score': task2_avg_me,
    'Avg Strict Evaluation Score': task2_avg_se
}
