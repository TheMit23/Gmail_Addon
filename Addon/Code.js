function onGmailMessageOpen(e) {
    var messageId = e.gmail.messageId;
    var accessToken = e.gmail.accessToken;
    GmailApp.setCurrentMessageAccessToken(accessToken);
    var message = GmailApp.getMessageById(messageId);
  
    var subject = message.getSubject();
    var sender = message.getFrom();
    
    // Mocking the analysis result for demonstration purposes
    var mockScore = 75;
    var mockVerdict = "Suspicious sender domain.";
    return buildResultCard(subject, sender, mockScore, mockVerdict);
  }
  
  function buildResultCard(subject, sender, score, verdict) {
    var card = CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader()
        .setTitle("Security Scan")
        .setSubtitle("Analyzing current email"));
        
    var section = CardService.newCardSection().setHeader("Email Details");
    section.addWidget(CardService.newTextParagraph().setText("<b>Sender:</b> " + sender));
    section.addWidget(CardService.newTextParagraph().setText("<b>Subject:</b> " + subject));
    
    var resultSection = CardService.newCardSection().setHeader("Scan Result");
    resultSection.addWidget(CardService.newTextParagraph().setText("<b>Maliciousness Score:</b> " + score + "/100"));
    resultSection.addWidget(CardService.newTextParagraph().setText("<b>Verdict:</b> " + verdict));
    
    card.addSection(section);
    card.addSection(resultSection);
    
    return card.build();
  }
  