function onGmailMessageOpen(e) {
  try {
    var messageId = e.gmail.messageId;
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    var message = GmailApp.getMessageById(messageId);
    // Basic Email data
    var subject = message.getSubject() || "No Subject";
    var sender = message.getFrom() || "Unknown Sender";
    var body = message.getPlainBody() || "";
    // Advanced Email Data
    var replyTo = message.getReplyTo() || sender; 
    var authResults = message.getHeader("Authentication-Results") || ""; 
    var returnPath = message.getHeader("Return-Path") || "";
    
    //Connect to the backend server
    var url = "https://ladder-specimen-chariot.ngrok-free.dev/analyze"; 
    
    var payload = {
      "sender": sender,
      "subject": subject,
      "body": body,
      "reply_to": replyTo,
      "auth_results": authResults,
      "return_path": returnPath
    };
    
    // POST request details
    var options = {
      "method": "post",
      "contentType": "application/json",
      "payload": JSON.stringify(payload),
      "muteHttpExceptions": true // Read exception
    };
    
    var response = UrlFetchApp.fetch(url, options);
    var responseCode = response.getResponseCode();
    var responseText = response.getContentText();
    
    if (responseCode !== 200) {
      return buildResultCard(subject, sender, 0, "Server Error", ["Backend returned status: " + responseCode, "Response: " + responseText]);
    }
    
    var result = JSON.parse(responseText);
    return buildResultCard(subject, sender, result.score, result.verdict, result.findings);
    
  } catch (error) {
    return buildResultCard("Error", "Error", 0, "Connection Failed", [error.message]);
  }
}


function buildResultCard(subject, sender, score, verdict, findings) {
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle("Security Scan")
      .setSubtitle("Runtime Email Analysis"));
      
  // Email details
  var detailsSection = CardService.newCardSection()
    .setHeader("Email Details");
  detailsSection.addWidget(CardService.newTextParagraph().setText("<b>Sender:</b> " + sender));
  detailsSection.addWidget(CardService.newTextParagraph().setText("<b>Subject:</b> " + subject));
  card.addSection(detailsSection);
  
  var resultSection = CardService.newCardSection()
    .setHeader("Scan Result");
    
  resultSection.addWidget(CardService.newTextParagraph().setText("<b>Maliciousness Score:</b> " + score + "/100"));
  
  // Design
  var verdictColor = (score >= 75) ? "#FF0000" : (score >= 40) ? "#FFA500" : "#008000";
  resultSection.addWidget(CardService.newTextParagraph().setText("<b>Verdict:</b> <font color='" + verdictColor + "'>" + verdict + "</font>"));
  
  // תיקון הצגת הממצאים
  if (findings && findings.length > 0) {
    var reasonsText = "<b>Analysis Reasons:</b><br>";
    for (var i = 0; i < findings.length; i++) {
      // כאן הקסם: ניגשים ל-description של האובייקט
      var description = findings[i].description;
      var severity = findings[i].severity;
      
      // בונוס: הוספת אייקון לפי חומרה
      var icon = (severity >= 3) ? "🔴 " : (severity >= 2) ? "🟠 " : "⚪ ";
      reasonsText += icon + description + "<br>";
    }
    resultSection.addWidget(CardService.newTextParagraph().setText(reasonsText));
  }
  
  card.addSection(resultSection);
  return card.build();
}
