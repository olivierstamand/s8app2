function getEmails() {
    var options =
    {
        url: ResolveUrl("~/home/emails"),
        type: "POST",
        data: { __RequestVerificationToken: $("#__RequestVerificationToken").val() },
        success: function (status) {
            $("#emailData").empty();
            $.each(status, function (index, item) {
                $("#emailData").append($('<div>').text(item));
            });
        },
        error: function (info) {
            alert(info);
        }
    };

    $.ajax(options);
}